use crate::{
    governance::GovernanceJobCommand,
    ports::{GovernanceJobQueue, StoreError},
};

#[derive(Clone)]
pub struct SqsGovernanceJobQueue {
    sqs: aws_sdk_sqs::Client,
    queue_url: String,
}

impl SqsGovernanceJobQueue {
    pub fn new(sqs: aws_sdk_sqs::Client, queue_url: impl Into<String>) -> Self {
        Self {
            sqs,
            queue_url: queue_url.into(),
        }
    }
}

impl GovernanceJobQueue for SqsGovernanceJobQueue {
    async fn enqueue(&self, command: GovernanceJobCommand) -> Result<(), StoreError> {
        let body = serde_json::to_string(&command).map_err(|error| {
            StoreError::Permanent(format!(
                "governance queue command serialization failed: {error}"
            ))
        })?;
        self.sqs
            .send_message()
            .queue_url(&self.queue_url)
            .message_body(body)
            .message_group_id(&command.job_id)
            .message_deduplication_id(format!(
                "{}:{}:{}",
                command.job_id, command.expected_revision, command.failure_attempt
            ))
            .send()
            .await
            .map_err(|error| {
                StoreError::Transient(format!("governance queue send failed: {error}"))
            })?;
        Ok(())
    }
}
