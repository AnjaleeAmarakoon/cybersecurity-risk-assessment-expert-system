% Cybersecurity Risk Assessment Expert System for Individual Users
% SWI-Prolog CLI implementation
% Knowledge rules are based on the authoritative sources listed in the report/README.
% The overall assessment band is a project-specific educational aggregation of matched weaknesses;
% it is NOT an official NIST or CISA risk rating.

:- dynamic answer/2.

start :-
    retractall(answer(_,_)),
    nl,
    writeln('=============================================================='),
    writeln(' CYBERSECURITY RISK ASSESSMENT EXPERT SYSTEM - INDIVIDUAL USERS'),
    writeln('=============================================================='),
    writeln('Answer each question with yes. or no. (include the full stop).'),
    writeln('This tool provides educational guidance, not a formal security audit.'),
    nl,
    ask_all,
    findall(Id-Finding-Recommendation-Source-Severity,
            risk_rule(Id, Finding, Recommendation, Source, Severity),
            Risks),
    print_report(Risks),
    retractall(answer(_,_)).

ask_all :-
    ask(mfa_email, 'Do you use MFA on your primary email account?'),
    ask(mfa_important, 'Do you use MFA on financial and other important accounts that offer it?'),
    ask(mfa_password_manager, 'If you use a password manager, is MFA enabled on it? (answer yes if you do not use one yet)'),
    ask(unique_passwords, 'Do you use a different password for each important account?'),
    ask(password_length, 'For single-factor accounts, are your passwords/passphrases at least 15 characters long?'),
    ask(password_manager, 'Do you use a reputable password manager?'),
    ask(default_passwords_changed, 'Have you changed default manufacturer/admin passwords on devices and services you control?'),
    ask(phishing_verify, 'Do you verify unexpected messages before clicking links or opening attachments?'),
    ask(no_sensitive_reply, 'Do you avoid sending passwords, one-time codes, or sensitive information in response to unsolicited messages?'),
    ask(report_phishing, 'Do you report and delete suspicious/phishing messages?'),
    ask(auto_updates, 'Are automatic software updates enabled where supported?'),
    ask(prompt_updates, 'Do you install critical/security updates promptly?'),
    ask(browser_av_updated, 'Do you keep your web browser and antivirus/security software updated?'),
    ask(supported_software, 'Are the devices/software you use for sensitive activity still receiving security updates?'),
    ask(antivirus, 'Is antivirus/anti-malware protection enabled and maintained where appropriate?'),
    ask(regular_backups, 'Do you regularly back up important personal data?'),
    ask(backup_disconnected, 'If you use an external backup drive, is it disconnected/safely stored when not backing up? (yes if not applicable)'),
    ask(backup_tested, 'Do you periodically verify that your important backups are usable/recoverable?'),
    ask(device_encryption, 'Is storage encryption enabled on your computer/mobile device?'),
    ask(removable_encryption, 'Are removable drives that contain important data encrypted? (yes if not applicable)'),
    ask(file_protection, 'Are sensitive documents/files protected with encryption or equivalent secure storage?'),
    ask(recovery_keys, 'Are encryption recovery keys/passwords stored safely? (yes if not applicable)'),
    ask(public_wifi_sensitive, 'Do you avoid sensitive activities on public Wi-Fi unless you have a secure connection?'),
    ask(public_wifi_vpn, 'When you use public Wi-Fi, do you use a trusted VPN/secure access method? (yes if you never use public Wi-Fi)'),
    ask(standard_account, 'Do you normally use a standard (non-administrator) account for everyday computer activity?').

ask(Key, Question) :-
    format('~w (yes/no): ', [Question]),
    read(Response),
    normalize_answer(Response, Normalized),
    assertz(answer(Key, Normalized)), nl.

normalize_answer(yes, yes) :- !.
normalize_answer(y, yes) :- !.
normalize_answer(no, no) :- !.
normalize_answer(n, no) :- !.
normalize_answer(_, no) :-
    writeln('Unrecognized answer; treated as no for conservative assessment.').

no(Key) :- answer(Key, no).

% -----------------------------
% Sourced IF-THEN risk rules
% -----------------------------
risk_rule(r01, 'MFA is not enabled on the primary email account', 'Enable MFA on the primary email account.', 'S1,S2', core) :- no(mfa_email).
risk_rule(r02, 'MFA is not enabled on important accounts', 'Enable MFA on banking, financial, shopping, social and other important accounts that offer it.', 'S2', core) :- no(mfa_important).
risk_rule(r03, 'Password manager lacks MFA protection', 'Enable MFA on the password manager account.', 'S5', high) :- no(mfa_password_manager).
risk_rule(r04, 'Passwords are reused across accounts', 'Use a unique password for every account.', 'S4,S5', core) :- no(unique_passwords).
risk_rule(r05, 'Single-factor passwords are shorter than the NIST minimum used by this assessment', 'Use passwords/passphrases of at least 15 characters for single-factor authentication.', 'S11', high) :- no(password_length).
risk_rule(r06, 'No password manager is used', 'Use a reputable password manager to generate and store long, random, unique passwords.', 'S4,S5,S6', medium) :- no(password_manager).
risk_rule(r07, 'Default manufacturer/admin passwords may remain in use', 'Replace default passwords with unique strong credentials.', 'S6,S10', high) :- no(default_passwords_changed).
risk_rule(r08, 'Unexpected messages may be opened without verification', 'Verify unexpected messages through a trusted channel before opening links or attachments.', 'S1,S4', core) :- no(phishing_verify).
risk_rule(r09, 'Sensitive credentials may be provided in response to unsolicited messages', 'Never provide passwords, one-time codes or sensitive information in response to unsolicited messages; independently verify requests.', 'S1,S4', high) :- no(no_sensitive_reply).
risk_rule(r10, 'Phishing messages may not be reported and deleted', 'Report phishing using the available reporting mechanism and delete the message without interacting with links.', 'S1,S4', medium) :- no(report_phishing).
risk_rule(r11, 'Automatic software updates are disabled', 'Enable automatic updates where supported.', 'S3,S4', core) :- no(auto_updates).
risk_rule(r12, 'Critical/security updates are delayed', 'Install critical and security updates promptly.', 'S3', core) :- no(prompt_updates).
risk_rule(r13, 'Browser or security software may be outdated', 'Keep web browsers and antivirus/security software updated.', 'S3', high) :- no(browser_av_updated).
risk_rule(r14, 'Unsupported software/devices are used for sensitive activity', 'Upgrade or replace products that no longer receive security updates.', 'S10', high) :- no(supported_software).
risk_rule(r15, 'Malware protection is absent, disabled or not maintained', 'Install, enable and maintain up-to-date antivirus/anti-malware protection where appropriate.', 'S6', medium) :- no(antivirus).
risk_rule(r16, 'Important data is not backed up regularly', 'Create regular backups to a secure external drive or properly vetted cloud service.', 'S6,S7', core) :- no(regular_backups).
risk_rule(r17, 'External backup media may remain exposed while connected', 'Disconnect and safely store external backup media when not actively backing up.', 'S7', medium) :- no(backup_disconnected).
risk_rule(r18, 'Backups are not checked for recoverability', 'Periodically verify/test important backups.', 'S6', medium) :- no(backup_tested).
risk_rule(r19, 'Device storage encryption is not enabled', 'Enable system/device encryption.', 'S7', high) :- no(device_encryption).
risk_rule(r20, 'Important data on removable media is not encrypted', 'Encrypt removable media containing important information.', 'S7', medium) :- no(removable_encryption).
risk_rule(r21, 'Sensitive documents/files lack encryption or equivalent protection', 'Use file encryption or suitable protected storage for sensitive files.', 'S7', medium) :- no(file_protection).
risk_rule(r22, 'Encryption recovery keys/passwords are not stored safely', 'Store recovery keys and encryption passwords securely.', 'S7', medium) :- no(recovery_keys).
risk_rule(r23, 'Sensitive activity may occur on public Wi-Fi without a secure connection', 'Avoid sensitive activity on public Wi-Fi unless using a secure connection such as a trusted VPN.', 'S8', high) :- no(public_wifi_sensitive).
risk_rule(r24, 'Public Wi-Fi is used without trusted secure access', 'Use a trusted VPN or other approved secure access method on public Wi-Fi.', 'S8', medium) :- no(public_wifi_vpn).
risk_rule(r25, 'Administrator privileges are used for routine daily activity', 'Use a standard user account for daily activity and reserve administrator access for tasks that require it.', 'S7', medium) :- no(standard_account).

print_report(Risks) :-
    nl, writeln('==================== ASSESSMENT RESULT ===================='),
    length(Risks, Count),
    count_core(Risks, CoreCount),
    assessment_level(Count, CoreCount, Level),
    format('Assessment level: ~w~n', [Level]),
    format('Matched security weaknesses: ~w of 25~n', [Count]),
    writeln('Note: This level is a project-specific educational summary, not an official NIST/CISA rating.'),
    nl,
    ( Risks = [] ->
        writeln('No weaknesses were identified from the answers provided. Continue reviewing security practices regularly.')
    ;
        writeln('Identified weaknesses and recommendations:'),
        print_risks(Risks, 1)
    ),
    writeln('===========================================================').

count_core(Risks, Count) :-
    findall(1, member(_-_-_-_-core, Risks), CoreList),
    length(CoreList, Count).

% Project-specific aggregation heuristic, not a sourced NIST/CISA risk scale.
assessment_level(_, CoreCount, 'SIGNIFICANT IMPROVEMENT NEEDED') :- CoreCount >= 2, !.
assessment_level(Count, _, 'SIGNIFICANT IMPROVEMENT NEEDED') :- Count >= 10, !.
assessment_level(Count, _, 'IMPROVEMENT NEEDED') :- Count >= 4, !.
assessment_level(_, _, 'GOOD BASELINE - CONTINUE IMPROVING').

print_risks([], _).
print_risks([Id-Finding-Recommendation-Source-Severity|Rest], N) :-
    format('~n~w. ~w [~w, ~w]~n', [N, Finding, Id, Severity]),
    format('   Recommendation: ~w~n', [Recommendation]),
    format('   Source reference(s): ~w~n', [Source]),
    N2 is N + 1,
    print_risks(Rest, N2).
