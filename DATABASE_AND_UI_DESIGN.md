# e-OB Kenya — Database & Screen Design v1

## Core design decision
The occurrence itself is immutable in history: substantive edits create a version snapshot and a reason rather than silently overwriting the prior record.

## Main relationships
Station 1--N Users
Station 1--N Occurrences
Occurrence 1--N Persons
Occurrence 1--N Assignments
Occurrence 1--N Actions
Occurrence 1--N Versions
Occurrence 1--N Approvals
Occurrence 1--N Attachments
All security-sensitive activity -> Audit Log

## Main e-OB screen
1. Occurrence identification
2. Occurrence details
3. Reporting person
4. Initial action
5. Submit / save draft

## Next screens
- OB register with filters
- OB detail + chronological action timeline
- Amendment screen with mandatory reason
- Supervisor review / approval
- Investigation assignment
- Station dashboard
- User/role administration
- Audit search

## Security requirements
- Station-scoped authorization
- Least privilege
- MFA for privileged roles
- Encrypt data in transit and at rest
- Audit access, create, amend, approve, export and administrative actions
- No hard delete of operational occurrences
- Controlled attachment storage
- Backup and recovery testing
- Retention and disposal rules approved before production

## Legal alignment note
The design should be validated against the current National Police Service Standing Orders and other applicable Kenyan law before production. The Standing Orders are current through amendments published in 2025.
