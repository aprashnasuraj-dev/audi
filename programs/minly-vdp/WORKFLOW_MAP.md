# Minly Normal Workflow Map

Status: Phase 1 baseline map for authorization-first testing.

This document separates **publicly observed workflows** from **authenticated workflows that must be confirmed manually after Account A and Account B exist**. Do not infer hidden endpoints or test third-party services.

## 1. Public / anonymous website surface

Observed from Minly's public website and indexed pages:

### Home and discovery

- home page and category browsing;
- celebrity/profile browsing;
- online event discovery;
- English/Arabic presentation;
- links to mobile application downloads;
- support/help content;
- business and talent-enrollment entry points.

Authorization relevance: these pages establish identifiers, navigation patterns, and object types, but public content itself is not an authorization issue.

### Celebrity/profile workflow

Normal path:

1. browse or search for a celebrity;
2. open a celebrity profile;
3. view available engagement options and pricing;
4. choose an offered interaction when available.

Potential object classes to record after login: celebrity identifier, service/offer identifier, request identifier, and resulting user-owned order/content object.

### Personalized video request workflow

Publicly visible request UI indicates a flow containing:

- recipient selection (self or someone else);
- From / To fields;
- occasion selection;
- instructions;
- optional mobile number;
- optional WhatsApp delivery choice;
- public/private publication preference;
- promo-code entry.

Authorization relevance: any request object created by Account A or B should remain bound to its owner. Testing should use only benign test content and researcher-owned objects.

### Events

The public site advertises live and on-demand online events.

Expected normal flow to verify manually:

1. browse an event;
2. view event details;
3. authenticate when required;
4. acquire an entitlement/ticket only if intentionally performing a legitimate transaction;
5. view owned event access/history.

Authorization relevance: ticket, event-access, entitlement, receipt, or on-demand media objects must not cross Account A/B boundaries.

### Support

The public site exposes a support/help area and support contact channel.

Authorization relevance: if authenticated support tickets exist, verify only whether Account A can access Account A tickets and Account B can access Account B tickets. Do not interact with tickets belonging to any other user.

## 2. Official mobile-app workflows confirmed from store listings

Both official app listings describe these ordinary-user capabilities:

- browse/connect with actors, singers, athletes, influencers, and other celebrities;
- request a personalized celebrity video message;
- privately chat with celebrities using text and voice messages;
- attend Minly Live interactive online concerts;
- use in-app purchases for Minly experiences.

The iOS listing identifies Minly as an iPhone app and explicitly labels messaging/chat, user-generated content, and in-app purchases. The Android listing shows the same personalized-video, private text/voice chat, and Minly Live flows.

Authorization implications to verify after Account A and Account B exist:

- private chat/thread ownership;
- personalized-video request ownership;
- request status/history isolation;
- event entitlement/access isolation;
- in-app purchase/order history isolation;
- any account-bound downloadable or streamable media;
- notification ownership;
- account deletion/data-management controls.

Do not test Apple, Google Play, payment processors, analytics providers, messaging providers, or other third parties directly.

## 3. Account lifecycle — verify after creation

Minly's privacy policy states that account registration may collect account/profile information and that logged-in users can request account deletion through account settings.

Confirm manually for Account A and Account B on the website first, then compare Android/iOS where available:

- registration;
- verification step(s);
- login;
- logout;
- profile view;
- profile edit;
- account settings;
- account deletion entry point;
- password/recovery flow, without stress testing or rate-limit testing.

Record only the visible workflow and the minimum request/response metadata needed for authorization checks.

## 4. Authenticated engagement — verify after creation

The platform terms describe user Content Requests to celebrities. Public website/app materials also advertise personalized videos, private text/voice messaging, online events, and purchase flows.

After login, map which of the following are actually present for ordinary users:

- favorites/saved celebrities;
- personalized video request drafts or submitted requests;
- request status/history;
- private text/voice message threads;
- order/payment history;
- wallet/credit balance;
- event tickets/entitlements;
- downloadable or streamable purchased content;
- notifications;
- support tickets;
- profile/account settings;
- account deletion.

Do not test an item that does not exist in the current product.

## 5. Payment boundary

Minly's terms describe payment authorization and refund behavior. Authorization testing must not create financial harm or charge another person.

Rules:

- do not use someone else's payment method;
- do not attempt payment-method enumeration;
- do not attempt to bypass payment;
- do not place repeated orders;
- do not test payment processors directly if they are third-party services;
- prefer non-financial objects first;
- if a legitimate purchase is ever needed, use the researcher's own payment method and one minimal transaction.

## 6. Third-party boundary

A page, script, payment provider, analytics service, CDN, social platform, app store, or messaging service is not automatically in scope merely because Minly uses it.

If normal navigation leaves the exact Minly-owned in-scope asset, record the transition and stop testing that external service.

## 7. Authorization object inventory

Fill this table only with object classes observed through normal use. Do not commit live identifiers from real testing to the public repository.

| Object class | Exists? | Created/owned by user? | Candidate A/B comparison | Notes |
|---|---|---|---|---|
| User profile | To verify | Yes | Read/update | Ordinary account only |
| Account settings | To verify | Yes | Read/update | No destructive change until needed |
| Favorites/saved items | To verify | Likely | Read/update/delete | Test only if feature exists |
| Content/video request | Confirmed product feature | Yes | Read/update/cancel/status | Benign test data only |
| Order/receipt | To verify | Yes | Read | Avoid unnecessary purchase |
| Wallet/credits | To verify | Yes | Read | No value manipulation |
| Event entitlement | Confirmed product feature | Yes | Read/use | Only legitimate own entitlement |
| Purchased media | To verify | Yes | Read/download/stream | Own media only |
| Private text/voice thread | Confirmed app feature | Yes | Read/send | Avoid unnecessary celebrity interaction |
| Notification | To verify | Yes | Read | Own notifications only |
| Support ticket | To verify | Yes | Read/update | Own tickets only |
| Account deletion request | Confirmed policy capability | Yes | Initiate/cancel if supported | Use disposable research account only |

## 8. First-pass priority

Prioritize authorization checks that are reversible and do not require payment or third-party interaction:

1. profile/account settings;
2. favorites/saved objects;
3. benign draft/request objects, if drafts exist;
4. notification/history objects;
5. private messaging metadata only when a benign thread exists naturally;
6. support objects created by the researcher;
7. paid or entitlement objects only after lower-risk coverage is complete.

The objective is not to maximize request count. It is to establish whether owner identity is enforced consistently across the normal product workflows.
