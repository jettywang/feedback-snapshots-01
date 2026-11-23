# Local test setup

From the repository root, install the pinned dependencies and run the focused local baseline.

```sh
BUNDLE_FROZEN=true .feedback/bundle-env install --quiet
.feedback/bundle-env exec rspec -Ilib -Ispec --options /dev/null spec/mail/attachments_list_spec.rb spec/mail/body_spec.rb spec/mail/elements/received_element_spec.rb
```

Measured on macOS in 0.620 seconds. Tests use local fixtures and require no external service.
