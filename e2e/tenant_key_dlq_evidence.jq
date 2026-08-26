def tenant_key_dlq_body:
  (.Body | fromjson);

def tenant_key_dlq_messages_qualify($source; $offboard; $created; $expected):
  length == $expected and
  (map(.MessageId) | length == (unique | length)) and
  all(.[];
    (tenant_key_dlq_body) as $body |
    (.MessageId | type == "string" and
      length > 0 and length <= 256 and test("^[A-Za-z0-9-]+$")) and
    (.MD5OfBody | type == "string" and test("^[0-9A-Fa-f]{32}$")) and
    (.Attributes.DeadLetterQueueSourceArn == $source) and
    (.Attributes.SentTimestamp | type == "string" and
      test("^[1-9][0-9]{0,15}$")) and
    (.Attributes.SentTimestamp | tonumber < ($created * 1000)) and
    ($body | keys | sort ==
      ["action", "operation_id", "requested_at", "tenant_id"]) and
    ($body.tenant_id == "t1") and
    ($body.tenant_id != $offboard) and
    ($body.action | type == "string" and length > 0 and length <= 32) and
    (["ensure", "rotate", "activate", "rollback", "retire",
      "offboard", "reconcile"] | index($body.action) != null) and
    ($body.operation_id | type == "string" and
      length > 0 and length <= 256) and
    ($body.requested_at | type == "number" and
      floor == . and . > 0 and . < $created)
  );

def tenant_key_dlq_canonical_rows:
  sort_by(.MessageId)[]
  | (.Body | fromjson) as $body
  | [
      "TenantKeyOperationsDlqMessage",
      .MessageId,
      (.MD5OfBody | ascii_downcase),
      (.Attributes.SentTimestamp | tonumber | tostring),
      ($body.requested_at | tostring)
    ]
  | @tsv;
