# MugVPN E2E socket

Interface tests (layer U of the test plan) drive the real app through a socket it
opens only in a testing build (`MUGVPN_TESTING=1 tools/build.sh`) started with `MUGVPN_E2E=1`. The app then also:

- keeps its settings in the `com.mugvpn.app.e2e` defaults domain and its
  profiles under `$MUGVPN_E2E_HOME` (never the user's own),
- uses a **fake backend** instead of the helper: `connect` creates a fake
  management link; the test feeds openvpn's messages into it and reads what
  the app sent back. No tunnel, no root, no network;
- logs URLs it would open and notifications it would post instead of doing it;
- treats the JSON object in `$MUGVPN_E2E_FORCED` as settings an administrator
  forced (managed preferences), e.g. `{"silent_connection": true}`.

Socket: `$MUGVPN_E2E_SOCKET` (Unix, stream). One JSON object per line each
way. Every request gets `{"ok": true, ...}` or `{"ok": false, "error": "..."}`.

| cmd | arguments | answer |
|---|---|---|
| `ping` | | `{}` |
| `status` | | `icon`: `idle` \| `connecting` \| `connected`; `image`: the menu bar picture's name; `button_width`: the status item's width in points; `image_pixels`: opaque pixels in its picture; `tooltip` |
| `menu` | | `items`: tree of `{title, enabled, checked, children?}` — the status menu as it would open now |
| `click_menu` | `path`: titles from the top, e.g. `["stand-a", "Connect"]` | `{}` |
| `windows` | | `windows`: `[{id, kind, title, profile, appearance, controls: [{id, type, label, value, enabled, visible}]}]`; `appearance` is `aqua` or `darkAqua`; the status window's `log` control also has `highlights` (the kinds of marks in it: error, warning, success, timestamp, address, keyword) and `theme` (`light` or `dark`, as shown); each visible control also has `frame` ([x, y, width, height] in the window, y up) and `clipped`: its text does not fit its frame, or it sticks out of the window |
| `set` | `window`, `control`, `value` (string or bool) | `{}` — as the user would: a check box or popup also fires its action, a text field or text view tells its delegate; a `list` takes a row title, `tabs` a tab id |
| `press` | `window`, `control` | `{}` (a button) |
| `key` | `window`, `key`: `return` \| `escape` | `{}` |
| `close` | `window` | `{}` |
| `fake_feed` | `profile`, `lines`: openvpn management lines | `{}` |
| `fake_sent` | `profile` | `lines`: commands the app wrote to that link |
| `fake_close` | `profile` | `{}` — the management socket closes (openvpn exited) |
| `fake_helper` | | `starts`: profile names; `stops`: profile names; `bundles`: `{name: {split_dns, protection}}` of the last start; `unblocks`: how often the app asked to lift blocks |
| `fake_refuse` | `message` (or null) | `{}` — the next helper start fails with it |
| `fake_log` | `profile`, `text` | `{}` — what that connection's openvpn log says (routes, DNS), for conflict checks |
| `fake_helper_status` | `status`: `enabled` \| `requiresApproval` \| `notRegistered` | `{}` |
| `answer_open_panel` | `path` (or null for Cancel) | `{}` — the next open panel returns it |
| `command_import` | `path` | `{}` — as `MugVPN --command import <path>` from another program (asks first) |
| `open_files` | `paths` | `{}` — as if opened from Finder or dropped on the app |
| `system_event` | `event`: `willSleep` \| `didWake` \| `networkChanged` | `{}` — as if macOS sent it |
| `fake_blocks` | `names` | `{}` — the profiles whose kill switch blocks traffic, as the helper would report |
| `fake_network` | `netstat`, `scutil` (their outputs), `interfaces`: `{ip: interface}` (what `route get` says) | `{}` — the routing table and DNS the leak check sees (without it, the real ones) |
| `leak_check` | | `findings`: texts — runs the leak check now |
| `fake_http` | `responses`: `[{status, body, disposition?}]` | `{}` — queued answers for profile downloads |
| `http_requests` | | `requests`: `[{url, username, password}]` |
| `uninstall_log` | | `helper`: `[{keepProfiles}]` the helper was asked; `removed`: user paths the app would remove (logged, not removed); `trashed`: the app bundle it would move to the Trash. The same record goes to `$MUGVPN_E2E_HOME/uninstall.json` just before the app quits |
| `opened_urls` | | `urls` (Show in Finder adds `reveal:<path>`); `panels`: how many open panels the app has shown |
| `notifications` | | `items`: `[{title, text}]` |
| `rescan` | | `{}` |
| `quit` | | `{}` then the app exits |

Window kinds: `credentials`, `secret`, `challenge`, `confirm`, `string`,
`pkcs11`, `message`, `status`, `settings`, `about`, `import_url`, `error`,
`helper_setup`, `conflict`, `connections`.

Control types: `button`, `checkbox`, `popup`, `text`, `secure`, `label`, `list`
(`items`: row titles, `value`: the selected one), `tabs` (`items`: tab ids,
`value`: the shown one; controls of other tabs are not listed), `view`.

Control ids are stable (`username`, `password`, `response`, `save`, `ok`,
`cancel`, `error_text`, `prompt_text`, ...). They are also the controls'
accessibility identifiers, so the same ids work for VoiceOver checks (UI-20).
