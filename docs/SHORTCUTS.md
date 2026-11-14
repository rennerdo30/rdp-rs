# Keyboard shortcuts

Remora has two keyboard states:

- **Remora has the keyboard**: keys work the window, as listed under
  [Everywhere in Remora](#everywhere-in-remora).
- **The session has the keyboard** after you click into the remote picture:
  every key goes to the remote PC, except the few chords under
  [In a session](#in-a-session). The status bar says "Keyboard goes to the
  remote session" while this is so.

## In a session

| Keys | What they do |
|---|---|
| Click into the picture | Send the keyboard to the session |
| **Ctrl+Alt+Home** | Give the keyboard back to Remora |
| **Ctrl+Alt+K** | Open the command palette over the session; the session gets the keyboard back when it closes |
| **Ctrl+Alt+Break** | Full screen on or off. On a session shown on several monitors, back into its tab |
| Hold **Alt** | Show the toolbar while the key is down (the key still goes to the session) |

**Ctrl+Alt+Del** has no chord of its own, because Windows keeps it. Use the
keyboard button on the toolbar, **Send Ctrl+Alt+Del** in the side panel's
Session page, or the command palette.

**Windows key combinations** (Win, Alt+Tab, Alt+Esc, Ctrl+Esc, Alt+Space and
the menu key) go where the connection's **Windows keys** setting says: to this
PC, to the remote session, or to the remote session in full screen only (the
default). Set it on the editor's Advanced page or in the side panel's Session
page.

## Everywhere in Remora

| Keys | What they do |
|---|---|
| **Ctrl+K** or **Ctrl+Shift+P** | Open the command palette |
| **Ctrl+N** | New connection (in the group you are looking at) |
| **Ctrl+F** | Filter the connections in the sidebar by name, address, user, group or app |
| **Ctrl+Tab** / **Ctrl+Shift+Tab** | Next / previous tab (the Connections tab included) |
| **Ctrl+Shift+U** | Install the offered update |
| **Up** / **Down** | Move through the sidebar's connections (when no text field has the cursor) |
| **Esc** | Leave a text field; from the editor or Settings, back to Home |

## Home

| Keys | What they do |
|---|---|
| Type into the field at the top | Quick connect: a saved name, an address, or `user@host:port` |
| **Up** / **Down** | Pick another match for what you typed |
| **Enter** | Connect to the picked match, or open the chosen card |
| **Tab** / **Shift+Tab** | Move from the field through the cards and their buttons |
| **Esc** | Clear the field; from a card, back to the field |

## Connection editor

| Keys | What they do |
|---|---|
| **Enter** | Connect (in a group: **Connect all**) |
| **Ctrl+S** | Save |
| **Tab** / **Shift+Tab** | Next / previous field |
| **Esc** | Back to Home |

## Command palette

| Keys | What they do |
|---|---|
| Type | Search sessions, connections, apps, groups, settings and commands |
| **Up** / **Down**, **Tab** / **Shift+Tab** | Move through the results |
| **Page Up** / **Page Down** | Move a page |
| **Home** / **End** | First / last result |
| **Enter** | Run the highlighted result |
| **Esc**, or **Ctrl+K** again | Close |

## Session toolbar

When neither the session nor a text field has the keyboard, the toolbar of
the open session takes these keys:

| Keys | What they do |
|---|---|
| **Tab**, **Right** / **Shift+Tab**, **Left** | Move between its buttons |
| **Enter** or **Space** | Press the highlighted button |
| **Esc** | Leave the toolbar, or close its menu |

## Text fields

| Keys | What they do |
|---|---|
| **Ctrl+A** | Select all |
| **Ctrl+V** | Paste |

## Dialogs

When you quit with sessions open, Remora asks first: **Enter** quits,
**Esc** stays.
