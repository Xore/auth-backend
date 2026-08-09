<#-- #91: branded email shell. base/email's own template.ftl (the only
     upstream file this macro replaces) is deliberately bare -- just
     <html><body><#nested></body></html>, no header, no footer, no styling
     at all (confirmed against the real upstream source for this pinned
     Keycloak release). Every *BodyHtml message key content templates pull
     from (password-reset.ftl, email-verification.ftl, etc) renders as
     plain <p>/<a> tags with no class or id, so all styling here works by
     cascading onto bare tags -- none of those content templates or the
     message bundle itself are touched, keeping this presentation-only per
     #91's own constraint.

     Table-based layout with inline styles throughout, not the CSS classes
     xore-theme.css and login.css/account.css use elsewhere in this repo:
     email clients (Outlook chief among them) don't reliably support linked
     or even <style>-block CSS, so there is no email equivalent of this
     project's usual `styles=` theme.properties convention. The <style>
     block below is a deliberate exception -- progressive enhancement only,
     for clients that do honor prefers-color-scheme (Apple Mail, some Gmail
     apps), duplicating in spirit (never relying on) the inline light-theme
     styles beneath it. Every color is a literal hex value copied from
     xore-theme.css's own light/dark variable blocks, not a var() -- email
     HTML has no custom-property support to speak of.

     url.resourcesUrl (confirmed via FreeMarkerEmailTemplateProvider.java's
     own source for this release) can be genuinely absent -- ContextNotActiveException
     when an email is sent outside an active HTTP request (a scheduled task,
     for example), not a theoretical case. Guarded with <#if url??> below so
     that real, if rare, path degrades to a plain text header instead of
     failing the whole send. -->
<#macro emailLayout>
<!DOCTYPE html>
<html lang="${locale.language}" dir="${(ltr)?then('ltr','rtl')}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>APIARY</title>
<style>
  @media (prefers-color-scheme: dark) {
    .apiary-email-bg { background: #20201f !important; }
    .apiary-email-card { background: #242422 !important; border-color: rgba(255,255,255,.14) !important; }
    .apiary-email-text, .apiary-email-text p { color: #e9e6df !important; }
    .apiary-email-text a { color: #6da7ec !important; }
    .apiary-email-footer { color: #68635e !important; }
  }
</style>
</head>
<body class="apiary-email-bg" style="margin:0; padding:0; background:#f7f6f2; font-family: Arial, Helvetica, sans-serif;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f7f6f2;">
    <tr>
      <td align="center" style="padding: 32px 16px;">
        <table role="presentation" width="480" cellpadding="0" cellspacing="0" class="apiary-email-card" style="max-width:480px; width:100%; background:#fbfaf7; border:1px solid rgba(34,31,28,.09); border-radius:14px;">
          <tr>
            <td align="center" style="padding: 28px 32px 12px;">
              <#if url??>
                <img src="${url.resourcesUrl}/img/apiary-lockup-for-light.png" width="180" alt="APIARY" style="display:block; width:180px; max-width:100%; height:auto; border:0;">
              <#else>
                <span style="font-family: Arial, Helvetica, sans-serif; font-size:20px; font-weight:bold; letter-spacing:0.06em; color:#af593f;">APIARY</span>
              </#if>
            </td>
          </tr>
          <tr>
            <td class="apiary-email-text" style="padding: 8px 32px 32px; color:#2f2b27; font-size:14px; line-height:1.6;">
              <style>
                .apiary-email-text p { margin: 0 0 14px; }
                .apiary-email-text p:last-child { margin-bottom: 0; }
                .apiary-email-text a { color: #2a78d6; text-decoration: underline; }
              </style>
              <#nested>
            </td>
          </tr>
        </table>
        <table role="presentation" width="480" cellpadding="0" cellspacing="0" style="max-width:480px; width:100%;">
          <tr>
            <td align="center" class="apiary-email-footer" style="padding: 20px 16px 0; color:#66615b; font-size:11px; line-height:1.5;">
              This message was sent by ${realmName}. If you weren't expecting it, you can safely ignore it.
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
</#macro>
