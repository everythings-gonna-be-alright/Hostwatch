# 0016 The learning day: Hostwatch learns this Mac for a day

**Context.** The baseline learned in three waves in the first hour, trusting ordinary activity of signed apps from
signing facts alone. Everything else from the first day still landed in Needs You, hundreds of patterns to classify by
hand. The user asked for the first day to be spent learning what is typical, to spare that.

**Decision.** The baseline's waves run through a learning day: 5, 15 and 60 minutes, then every hour until its end, 24
hours by default (Settings: 1, 3 or 7 days, Extend by a Day, End Now, Learn This Mac Again). Each wave works as before
(rules for trusted signed apps and macOS), and sends other signed programs' patterns to the on-device model. After the
first hour, only patterns that recur (`BaselineLearner.recurs`: seen three times, over at least an hour) go, since a
one-off isn't typical. While learning, the model's sure Safe is applied (`triageOnDevice(applyAs:)`), source
"on-device", note "learned during the learning day", unless `aiSafeRefusal` refuses it (shells, interpreters,
sensitive files, high risk, 0013). After the learning day its answers are suggestions again. What the baseline policy
leaves for you (unsigned, ad-hoc, quarantined, downloaded or temp, high-risk) is never learned.

**Consequences.** The risk of learning is malware already on the Mac being learned as normal: the policy's signer
checks, recurrence, threat lists and stories guard against it, and a swapped or quarantined binary reopens what was
learned (`raise`). Learned decisions are automatic (baseline) or the AI's, below yours and your rules, and Patterns ▸
Rules undoes a learned app.
