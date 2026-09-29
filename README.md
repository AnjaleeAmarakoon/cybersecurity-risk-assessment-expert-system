# Cybersecurity Risk Assessment Expert System

A command-line expert system written in SWI-Prolog that helps individuals review their cybersecurity habits. It asks 25 yes/no questions, identifies potential weaknesses, and prints recommendations based on the answers.

This is an educational self-assessment. Its assessment levels are project-specific and are **not official NIST or CISA risk ratings** or a formal security audit.

## Requirements

- [SWI-Prolog](https://www.swi-prolog.org/Download.html) installed on your computer.
- A terminal with the `swipl` command available.

No additional Prolog packages are required. After installation, check that SWI-Prolog is available:

```sh
swipl --version
```

## Run the assessment

Open a terminal in this project directory and run:

```sh
swipl -q -s cybersecurity_risk_expert_system.pl -g start -t halt
```

The questionnaire starts immediately, prints the report after the final answer, and exits.

Alternatively, load the file in an interactive Prolog session:

```sh
swipl -s cybersecurity_risk_expert_system.pl
```

At the `?-` prompt, enter:

```prolog
start.
```

Run `start.` again to repeat the assessment, or enter `halt.` to exit.

### Answer format

Enter lowercase `yes.` or `no.` and press Enter. **Include the full stop** because the program reads Prolog terms. The abbreviations `y.` and `n.` also work.

```text
Do you use MFA on your primary email account? (yes/no): yes.
```

- Answer according to your current practices.
- For questions that explicitly say “yes if not applicable,” follow that instruction.
- An unrecognized, valid Prolog term is treated as `no` and produces a warning; the question is not repeated.
- Malformed Prolog input can cause a syntax error. If you omit the full stop, the program waits for the rest of the answer.

## What it checks

The 25 questions cover:

- Multi-factor authentication (MFA) for email, important accounts, and password managers.
- Password uniqueness, length, password-manager use, and default passwords.
- Phishing awareness, sensitive-information handling, and reporting suspicious messages.
- Software updates, supported devices/software, and malware protection.
- Regular backups, disconnected backup media, and recovery checks.
- Device, removable-media, and file encryption, plus recovery-key storage.
- Public Wi-Fi practices and everyday use of a non-administrator account.

## Understanding the report

Each `no` answer matches one weakness rule. The report shows the overall assessment level, the number of matched weaknesses out of 25, and each finding with its rule ID, severity, recommendation, and source-reference labels.

The assessment applies these conditions in order:

| Condition | Assessment level |
| --- | --- |
| At least 2 `core` weaknesses, or at least 10 total weaknesses | `SIGNIFICANT IMPROVEMENT NEEDED` |
| Otherwise, 4–9 total weaknesses | `IMPROVEMENT NEEDED` |
| Otherwise, 0–3 total weaknesses | `GOOD BASELINE - CONTINUE IMPROVING` |

Rules are labeled `core`, `high`, or `medium`. Only `core` has a separate threshold in the overall assessment; all matched rules count equally toward the total. Findings appear in rule order, rather than being sorted by severity.

For example, answering `yes.` to every question produces:

```text
Assessment level: GOOD BASELINE - CONTINUE IMPROVING
Matched security weaknesses: 0 of 25
```

A good baseline does not guarantee security: the result depends entirely on the answers and the checks implemented. The program does not scan devices, inspect accounts, or verify settings.

## Project structure and implementation

```text
.
├── README.md
└── cybersecurity_risk_expert_system.pl
```

The implementation is contained in one file:

| Predicate | Purpose |
| --- | --- |
| `start/0` | Clears previous answers, runs the questionnaire, prints the report, and clears answers after normal completion. |
| `ask_all/0` | Defines the 25 questions and their answer keys. |
| `ask/2`, `normalize_answer/2` | Read, normalize, and store responses. |
| `answer/2` | Stores answers dynamically in memory during the assessment. |
| `risk_rule/5` | Defines each rule's ID, finding, recommendation, source labels, severity, and triggering condition. |
| `count_core/2`, `assessment_level/3` | Calculate the overall assessment level. |
| `print_report/1`, `print_risks/2` | Format the results for the terminal. |

The program does not save answers or reports to files or send them over the network. If a run is interrupted, the next call to `start/0` clears any remaining answers.

To add a check, add a question with a unique key in `ask_all/0` and a corresponding `risk_rule/5` that checks `no(Key)`. Also update the hard-coded question total in the report and review the assessment thresholds and this README.

## Source references

The rules contain reference labels such as `S1`, `S2`, and `S11`. The source-file comments refer to a report/README bibliography, but no bibliography or report was supplied with this project. These labels are retained in the output; their mapping to specific publications is currently undocumented. Add the original source titles, URLs, and relevant sections before using the labels as verifiable citations.
