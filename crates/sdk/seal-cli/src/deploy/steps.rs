//! What a deploy does, step by step, the same on every cloud: said as it goes, or for
//! `--dry-run` listed with the commands that would change something, none of which runs.
//!
//! Every step looks before it changes anything (`ensure`), so running the same command again
//! after a failure picks up where it stopped and makes nothing twice. What a run made is kept
//! (`made`): when the run fails, it is listed with the commands that remove it, so a half-made
//! deployment is never left unexplained.

use serde_json::Value;

use super::cli::Cli;
use crate::{say, ui};

/// A resource this run created, and the command that removes it.
pub struct Made {
    pub what: String,
    pub remove: String,
}

pub struct Steps<'a> {
    pub cli: &'a Cli,
    pub dry: bool,
    pub lines: Vec<String>,
    pub made: Vec<Made>,
}

impl<'a> Steps<'a> {
    pub fn new(cli: &'a Cli, dry: bool) -> Self {
        Self { cli, dry, lines: Vec::new(), made: Vec::new() }
    }

    pub fn note(&mut self, text: String) {
        if self.dry {
            self.lines.push(text);
        } else {
            say!("{} {text}", ui::dim("·"));
        }
    }

    /// `CLI ARGS`'s output; `None` on a dry run, which lists the command instead.
    pub async fn change(&mut self, args: &[&str]) -> anyhow::Result<Option<Value>> {
        if self.dry {
            self.lines.push(format!("  {}", self.cli.line(args)));
            return Ok(None);
        }
        self.cli.json(args).await.map(Some)
    }

    /// The resource `show` finds, else the one `create` makes (said as `what`, recorded with
    /// `remove` as made by this run). A create that finds it there already, as one that timed
    /// out and is tried again can, counts as done. `None` only on a dry run of a create.
    pub async fn ensure(
        &mut self,
        what: &str,
        show: &[&str],
        create: &[&str],
        remove: &[&str],
    ) -> anyhow::Result<Option<Value>> {
        if let Some(found) = self.cli.show(show).await? {
            self.note(format!("{what}: using it"));
            return Ok(Some(found));
        }
        self.note(format!("{what}: creating"));
        if self.dry {
            self.lines.push(format!("  {}", self.cli.line(create)));
            return Ok(None);
        }
        match self.cli.json(create).await {
            Ok(_) => self.made.push(Made { what: what.to_owned(), remove: self.cli.line(remove) }),
            Err(e) if self.cli.already_exists(&e) => {}
            Err(e) => return Err(e),
        }
        self.cli
            .show(show)
            .await?
            .map(Some)
            .ok_or_else(|| anyhow::anyhow!("{what} was created but cannot be read back"))
    }

    /// Records `what` as made by this run (for a resource made by a step `ensure` does not fit).
    pub fn made(&mut self, what: &str, remove: &[&str]) {
        if !self.dry {
            self.made.push(Made { what: what.to_owned(), remove: self.cli.line(remove) });
        }
    }

    /// After a failure: what this run made, and how to finish or undo it.
    pub fn explain_failure(&self, again: &str) {
        if self.dry {
            return;
        }
        eprintln!();
        if self.made.is_empty() {
            eprintln!("nothing was created; fix the error and run `{again}` again");
            return;
        }
        eprintln!("this run created, before it stopped:");
        for m in &self.made {
            eprintln!("  {}", m.what);
        }
        eprintln!("run `{again}` again to finish (it reuses them), or remove them, newest first:");
        for m in self.made.iter().rev() {
            eprintln!("  {}", m.remove);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::cli::GCLOUD;
    use super::*;

    #[test]
    fn a_dry_run_lists_changes_and_records_nothing() {
        let mut steps = Steps::new(&GCLOUD, true);
        steps.note("router: creating".into());
        steps.made("router", &["compute", "routers", "delete", "r"]);
        assert_eq!(steps.lines, ["router: creating"]);
        assert!(steps.made.is_empty(), "a dry run makes nothing");
    }

    #[test]
    fn made_resources_are_removed_newest_first() {
        let mut steps = Steps::new(&GCLOUD, false);
        steps.made("service account", &["iam", "service-accounts", "delete", "sa"]);
        steps.made("router", &["compute", "routers", "delete", "r"]);
        let removes: Vec<_> = steps.made.iter().rev().map(|m| m.remove.as_str()).collect();
        assert_eq!(removes, ["gcloud compute routers delete r", "gcloud iam service-accounts delete sa"]);
    }
}
