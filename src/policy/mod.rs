//! Policy evaluation: the offline core that turns a host policy plus a command
//! into a single decision. No SSH, no MCP — fully testable in isolation.

mod command;
mod gate;
mod permission;

pub use gate::Evaluator;
pub use permission::{Permission, PermissionSet, Tool};

/// The outcome of evaluating a command against a rule set or a host policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Block the command.
    Deny,
    /// Prompt the user before running.
    Ask,
    /// Run without prompting.
    Allow,
    /// No rule matched. The caller resolves the fallback (fail-closed).
    Unset,
}

impl Decision {
    /// Restrictiveness rank used when combining the subcommands of one
    /// compound command. `Unset` ranks above `Allow` so that an unknown
    /// subcommand can never ride on an allowed sibling.
    fn compound_rank(self) -> u8 {
        match self {
            Decision::Deny => 3,
            Decision::Ask => 2,
            Decision::Unset => 1,
            Decision::Allow => 0,
        }
    }

    /// Combine two sibling subcommands of a compound command. Every
    /// subcommand must clear the bar independently, so the more restrictive
    /// decision wins.
    pub fn combine_compound(self, other: Decision) -> Decision {
        if self.compound_rank() >= other.compound_rank() {
            self
        } else {
            other
        }
    }
}
