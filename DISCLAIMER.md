# Disclaimer & Limitation of Liability

**Project:** `n8n-hubspot-ticket-satisfaction-detractor-escalation`
**Publisher:** DH Robin (dhRobin Systems)
**Applies to:** every file in this repository, including `workflow.json`, `escalation.js`, `env.example` and the documentation.

## 1. Purpose

This repository is an educational and architectural reference. It shows one way to receive signed customer-satisfaction survey webhooks, identify detractors, re-open and escalate the related HubSpot ticket, record an internal note, and alert people through Slack or PagerDuty. It is not a managed service, an incident-management product, a customer-success program or legal advice.

## 2. "As is", without warranty

The software is provided **"AS IS" and "AS AVAILABLE", without warranty of any kind**, express or implied. This includes, without limitation, warranties of merchantability, fitness for a particular purpose, title, non-infringement, accuracy, completeness and uninterrupted or error-free operation.

## 3. Automated changes to HubSpot

When `DRY_RUN=false`, the workflow changes live CRM data: it moves closed tickets back to an open stage, raises `hs_ticket_priority`, and creates notes associated with tickets. These changes are visible to your team, can trigger HubSpot workflows, SLAs, notifications and reports, and are not undone automatically. Ticket matching depends on the IDs your survey tool sends; when only a contact ID is available, the most recently modified ticket is used and may not be the one the customer meant. `SANDBOX_MODE=true` limits writes to sandbox or developer test portals, and you are responsible for the consequences once you disable it.

## 4. Alerts, paging and on-call

Slack messages and PagerDuty incidents cannot be recalled from everyone who received them. Alerts contain customer feedback, scores, customer names and ticket details. Make sure every destination channel and service is appropriate for that information. Paging people has real cost; configure `PAGERDUTY_MIN_SEVERITY` and escalation policies deliberately. Delivery is not guaranteed: networks, rate limits, retries or misconfiguration can delay, duplicate or drop alerts. **Do not rely on this workflow as your only escalation path for customer-critical issues.**

## 5. Webhook security

Security depends on keeping `WEBHOOK_SECRET` confidential, rotating it when exposed, serving n8n over HTTPS and keeping the replay tolerance short. Signature verification protects against forged requests but not against a compromised survey tool or n8n host.

## 6. Classification accuracy

Detractor thresholds, severity levels and critical keywords are heuristics. They can misclassify sarcasm, other languages, typos or non-standard scales. Review the configuration against your own survey design and keep humans in the loop for every response sent to a customer.

## 7. Third-party services

HubSpot, Slack, PagerDuty and n8n APIs, scopes, rate limits, subscription requirements and data formats may change at any time without notice. You are responsible for validating the workflow against current documentation and your account limits.

## 8. Data protection and compliance

The workflow processes customer feedback, customer names, masked email addresses, HubSpot record IDs and employee names. You are responsible for complying with the terms of service, acceptable-use and security policies of HubSpot, Slack, PagerDuty, n8n and any connected service; with data-protection law (for example GDPR or CCPA/CPRA), including lawful basis, purpose limitation and retention of n8n execution data; and with your internal data-classification rules.

## 9. Limitation of liability

To the maximum extent permitted by applicable law, in no event shall the author, DH Robin, dhRobin Systems or any contributor be liable for any direct, indirect, incidental, special, exemplary, punitive or consequential damages. This includes lost revenue, customers, profit, business, goodwill or data; missed, late, duplicated or misrouted escalations; unintended ticket changes; disclosure of information to unintended audiences; on-call or paging costs; and the cost of substitute services. It applies however caused and on any theory of liability, whether in contract, strict liability or tort (including negligence), arising in any way out of the use, misuse, inability to use or deployment of this software, even if advised of the possibility of such damage.

## 10. No affiliation

HubSpot, Slack, PagerDuty and n8n are trademarks of their respective owners. This project is independent and is not affiliated with, endorsed by or sponsored by any of them. All customer names, IDs, emails (such as `customer_1@example.com`), keys and domains in this repository are fictional or placeholders.

## 11. License

The software is licensed under the MIT License (see [LICENSE](LICENSE)). If anything here conflicts with the MIT License, the MIT License governs.

---

## ⚠️ Disclaimer & Liability Limitation

**Use at your own risk.** The code, workflows, and scripts provided in this repository (`n8n-hubspot-ticket-satisfaction-detractor-escalation`) are for educational and architectural demonstration purposes.

* **No Liability:** The author and dhRobin Systems assume no responsibility or liability for any direct, indirect, incidental, or consequential damages resulting from the use, misuse, or deployment of these scripts, including missed, delayed, duplicated or misrouted escalations and unintended ticket changes.
* **No Warranty:** All software, n8n JSON blueprints, and JavaScript modules are provided "AS IS" without warranty of any kind, express or implied, including but not limited to merchantability, fitness for a particular purpose, or non-infringement. Detractor classification, severity, ticket matching and alert delivery are not guaranteed to be accurate, complete or timely.
* **Production Testing Required:** Always test thoroughly in an isolated staging environment (for example a HubSpot developer test account or sandbox) with `SANDBOX_MODE=true` and `DRY_RUN=true` enabled before connecting live HubSpot credentials, Slack channels or PagerDuty services. Treat every ticket re-open, priority change, audit note and page as visible to your team and not silently reversible.
* **Third-Party APIs & Compliance:** Users are solely responsible for complying with the terms of service, rate limits, data privacy regulations (GDPR/CCPA), and security policies of HubSpot, Slack, PagerDuty and any connected services. That includes keeping webhook secrets confidential and rotated, sharing customer feedback only with people entitled to see it, and keeping human review in every customer-facing response this automation prompts.

The full disclaimer is also available in [DISCLAIMER.md](https://github.com/dhrobinsystems/n8n-hubspot-ticket-satisfaction-detractor-escalation/blob/main/DISCLAIMER.md).

## License

Released under the MIT License. Copyright (c) 2026 DH Robin (dhRobin Systems). See [LICENSE](https://github.com/dhrobinsystems/n8n-hubspot-ticket-satisfaction-detractor-escalation/blob/main/LICENSE).

License: MIT © 2026 dhRobin Systems · Provided as-is, see the disclaimer.
