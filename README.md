# WP-Graph-Mailer
Send all wp_mail() via Microsoft Graph (Application permissions). Supports large attachments (>3 MB) using Upload Sessions and Shared Mailbox (requires proper Graph/Exchange permissions).

Description

- Uses OAuth2 client credentials (Application Permissions).
- Sends via `/users/{FROM_UPN}/messages/{id}/send` so you can target a user or shared mailbox.
- Adds small attachments inline; large ones via Upload Session (chunked, default 4 MB chunk).
- Simple settings page under **Settings → WP Graph Mailer**, including a test form.

Permissions

Your Entra ID app must have **Mail.Send** and, for shared mailboxes, **Mail.Send.Shared** (Application). Admin consent required. Limit the app via **Application Access Policies** or **Exchange RBAC for Applications**.

Installation

1. Upload the ZIP via *Plugins → Add New → Upload* and activate.
2. Go to *Settings → WP Graph Mailer* and fill Tenant ID, Client ID, Client Secret, From UPN.
3. Click "Save".
4. Use the Test form or trigger any `wp_mail()` (contact forms, etc.).

Tags: mail, microsoft, graph, api, office365, azure, shared mailbox, attachments, wordpress
