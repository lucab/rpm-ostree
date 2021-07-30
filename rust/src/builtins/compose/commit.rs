//! CLI sub-command `compose commit`.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::cxxrsutil::{CxxResult, FFIGObjectWrapper};
use anyhow::{anyhow, Result};
use fn_error_context::context;
use indoc::printdoc;
use openat_ext::OpenatDirExt;
use ostree::RepoTransactionStats;
use std::pin::Pin;

/// Print statistics related to an ostree transaction.
pub fn print_ostree_txn_stats(mut stats: Pin<&mut crate::FFIOstreeRepoTransactionStats>) {
    let stats = &stats.gobj_wrap();
    printdoc!(
        "Metadata Total: {meta_total}
        Metadata Written: {meta_written}
        Content Total: {content_total}
        Content Written: {content_written}
        Content Cache Hits: {cache_hits}
        Content Bytes Written: {content_bytes}
        ",
        meta_total = stats.get_metadata_objects_total(),
        meta_written = stats.get_metadata_objects_written(),
        content_total = stats.get_content_objects_total(),
        content_written = stats.get_content_objects_written(),
        cache_hits = stats.get_devino_cache_hits(),
        content_bytes = stats.get_content_bytes_written()
    );
}

#[context("Writing commit-id to {}", target_path)]
pub fn write_commit_id(target_path: &str, revision: &str) -> CxxResult<()> {
    if target_path.is_empty() {
        return Err(anyhow!("empty target path").into());
    }
    if revision.is_empty() {
        return Err(anyhow!("empty revision content").into());
    }
    std::fs::write(target_path, revision)?;
    Ok(())
}

/// Logic for `--write-composejson-to`.
#[context("Writing compose JSON to {}", target_path)]
pub unsafe fn write_compose_json(
    target_path: &str,
    stats_ptr: *mut crate::FFIOstreeRepoTransactionStats,
    new_ref: &str,
    content_checksum: &str,
) -> CxxResult<()> {
    if target_path.is_empty() {
        return Err(anyhow!("empty target path").into());
    }
    // let json = json_gvariant_serialize(metadata);
    let stats = stats_ptr.as_mut().and_then(|s| Some(s.gobj_wrap()));
    let new_ref = None;
    let commit_version = None;
    let meta = assemble_compose_metadata(stats, new_ref, "", content_checksum, commit_version)?;
    let dirname = target_path;
    let filename = target_path;
    let dir = openat::Dir::open(dirname)?;
    dir.write_file_with(filename, 0o0644, |bufwr| -> Result<_> {
        serde_json::to_writer_pretty(bufwr, &meta)?;
        Ok(())
    })?;
    Ok(())
}

type ComposeMeta = Vec<(&'static str, serde_json::Value)>;

fn assemble_compose_metadata(
    txn_stats: Option<RepoTransactionStats>,
    new_ref: Option<&str>,
    new_revision: &str,
    content_checksum: &str,
    commit_version: Option<&str>,
) -> Result<ComposeMeta> {
    let mut meta = vec![];

    if let Some(nr) = new_ref {
        meta.push(("ref", serde_json::to_value(nr)?));
    }

    // Lift transaction statistics into compose properties, if any.
    if let Some(s) = txn_stats {
        meta.push((
            "ostree-n-metadata-total",
            serde_json::to_value(s.get_metadata_objects_total())?,
        ));
        meta.push((
            "ostree-n-metadata-written",
            serde_json::to_value(s.get_metadata_objects_written())?,
        ));
        meta.push((
            "ostree-n-content-total",
            serde_json::to_value(s.get_content_objects_total())?,
        ));
        meta.push((
            "ostree-n-content-written",
            serde_json::to_value(s.get_content_objects_written())?,
        ));
        meta.push((
            "ostree-n-cache-hits",
            serde_json::to_value(s.get_devino_cache_hits())?,
        ));
        meta.push((
            "ostree-content-bytes-written",
            serde_json::to_value(s.get_content_bytes_written())?,
        ));
    }

    meta.push(("ostree-commit", serde_json::to_value(new_revision)?));
    meta.push((
        "ostree-content-checksum",
        serde_json::to_value(content_checksum)?,
    ));

    if let Some(cv) = commit_version {
        meta.push(("ostree-version", serde_json::to_value(cv)?));
    }

    Ok(meta)
    /*
          /* Since JavaScript doesn't have 64 bit integers and hence neither does JSON,
           * store this as a string:
           * https://stackoverflow.com/questions/10286204/the-right-json-date-format
           * */
          { guint64 commit_ts = ostree_commit_get_timestamp (new_commit);
            g_autofree char *commit_ts_iso_8601 = rpmostree_timestamp_str_from_unix_utc (commit_ts);
            g_variant_builder_add (&builder, "{sv}", "ostree-timestamp", g_variant_new_string (commit_ts_iso_8601));
          }
    */
    
    /*
      const char *inputhash = NULL;
      (void)g_variant_lookup (new_commit_inline_meta, "rpmostree.inputhash", "&s", &inputhash);
      /* We may not have the inputhash in the split-up installroot case */
      if (inputhash)
        g_variant_builder_add (&builder, "{sv}", "rpm-ostree-inputhash", g_variant_new_string (inputhash));

      g_autofree char *parent_revision = ostree_commit_get_parent (new_commit);
      if (parent_revision)
        {
          /* don't error if the parent doesn't exist */
          gboolean parent_exists = false;
          if (!ostree_repo_has_object (repo, OSTREE_OBJECT_TYPE_COMMIT, parent_revision,
                                       &parent_exists, cancellable, error))
            return FALSE;

          if (parent_exists)
            {
              g_autoptr(GVariant) diffv = NULL;
              if (!rpm_ostree_db_diff_variant (repo, parent_revision, new_revision,
                                               TRUE, &diffv, cancellable, error))
                return FALSE;
              g_variant_builder_add (&builder, "{sv}", "pkgdiff", diffv);
            }
        }

      g_autoptr(GVariant) composemeta_v = g_variant_builder_end (&builder);

    */
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_commit_id() {
        write_commit_id("", "foo").unwrap_err();
        write_commit_id("/foo", "").unwrap_err();

        let tmpdir = tempfile::tempdir().unwrap();
        let filepath = tmpdir.path().join("commit-id");
        let expected_id = "my-revision-id";
        write_commit_id(&filepath.to_string_lossy(), &expected_id).unwrap();
        let read = std::fs::read_to_string(&filepath).unwrap();
        assert_eq!(read, expected_id);
    }
}
