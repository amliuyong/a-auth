use super::*;
use aws_sdk_sqs::types::{BatchResultErrorEntry, SendMessageBatchResultEntry};

fn success(id: &str) -> SendMessageBatchResultEntry {
    SendMessageBatchResultEntry::builder()
        .id(id)
        .message_id(format!("message-{id}"))
        .md5_of_message_body("md5")
        .build()
        .unwrap()
}

fn failure(id: &str, sender_fault: bool) -> BatchResultErrorEntry {
    BatchResultErrorEntry::builder()
        .id(id)
        .sender_fault(sender_fault)
        .code(if sender_fault {
            "InvalidMessageContents"
        } else {
            "ServiceUnavailable"
        })
        .build()
        .unwrap()
}

#[test]
fn batch_output_preserves_per_entry_success_and_failure_classes() {
    let output = aws_sdk_sqs::operation::send_message_batch::SendMessageBatchOutput::builder()
        .set_successful(Some(vec![success("event_0"), success("event_03")]))
        .set_failed(Some(vec![
            failure("event_1", true),
            failure("event_2", false),
        ]))
        .build()
        .unwrap();

    let outcomes = classify_batch_output(4, &output);

    assert_eq!(outcomes[0], SecurityEventFallbackOutcome::Enqueued);
    assert!(matches!(
        outcomes[1],
        SecurityEventFallbackOutcome::Permanent(_)
    ));
    assert!(matches!(
        outcomes[2],
        SecurityEventFallbackOutcome::Retryable(_)
    ));
    assert!(matches!(
        outcomes[3],
        SecurityEventFallbackOutcome::Retryable(_)
    ));
}

#[test]
fn batch_output_retries_duplicate_or_conflicting_entries() {
    let output = aws_sdk_sqs::operation::send_message_batch::SendMessageBatchOutput::builder()
        .set_successful(Some(vec![success("event_0"), success("event_0")]))
        .set_failed(Some(vec![
            failure("event_1", true),
            failure("event_1", false),
        ]))
        .build()
        .unwrap();

    let outcomes = classify_batch_output(2, &output);

    assert!(outcomes
        .iter()
        .all(|outcome| matches!(outcome, SecurityEventFallbackOutcome::Retryable(_))));
}

#[test]
fn batch_service_error_retries_only_unhandled_or_throttled_codes() {
    use aws_sdk_sqs::error::ErrorMetadata;
    use aws_sdk_sqs::operation::send_message_batch::SendMessageBatchError;
    use aws_sdk_sqs::types::error::{QueueDoesNotExist, RequestThrottled};

    assert!(batch_service_error_is_permanent(
        &SendMessageBatchError::QueueDoesNotExist(QueueDoesNotExist::builder().build())
    ));
    assert!(!batch_service_error_is_permanent(
        &SendMessageBatchError::RequestThrottled(RequestThrottled::builder().build())
    ));
    assert!(!batch_service_error_is_permanent(
        &SendMessageBatchError::generic(
            ErrorMetadata::builder()
                .code("FutureRetryableServiceError")
                .build(),
        )
    ));

    let construction = aws_sdk_sqs::error::SdkError::<SendMessageBatchError>::construction_failure(
        std::io::Error::other("invalid request construction"),
    );
    assert!(matches!(
        classify_batch_send_error(construction),
        StoreError::Permanent(_)
    ));
}
