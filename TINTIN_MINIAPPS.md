# TinTin Mini-App SDK

> **License**: MIT — this SDK specification and the reference SDK library are MIT-licensed so that third-party developers can adopt them freely.
> **Status**: Design specification — not yet implemented.

## Architecture

A mini-app is a self-contained web application (HTML + CSS + JavaScript) that runs inside a sandboxed WebView within the TinTin host app. The mini-app communicates with the host through a JS bridge (`window.TinTin`), which exposes a set of controlled APIs.

```
┌─────────────────────────────┐
│     TinTin Host App         │
│  ┌───────────────────────┐  │
│  │   WebView (sandbox)   │  │
│  │   ┌─────────────────┐ │  │
│  │   │  Mini-App       │ │  │
│  │   │  (HTML/CSS/JS)  │ │  │
│  │   └──────┬──────────┘ │  │
│  │          │ JS Bridge   │  │
│  │          v             │  │
│  │  ┌──────────────┐     │  │
│  │  │  SDK Runtime  │     │  │
│  │  └──────┬───────┘     │  │
│  │         │              │  │
│  │  ┌──────v───────┐     │  │
│  │  │  Native APIs  │     │  │
│  │  └──────────────┘     │  │
│  └───────────────────────┘  │
└─────────────────────────────┘
```

## Mini-App Package Format

A mini-app is distributed as a signed ZIP archive (`.tma` — TinTin Mini App) containing:

```
app.tma
├── manifest.json          # Required: app metadata
├── icon.png               # Required: 128×128 app icon
├── index.html             # Required: entry point
├── style.css              # Optional
├── script.js              # Optional
└── assets/                # Optional: images, fonts, etc.
```

### manifest.json

```json
{
  "app_id": "com.example.myapp",
  "name": "My App",
  "version": "1.0.0",
  "description": "A mini-app example",
  "icon": "icon.png",
  "entry": "index.html",
  "permissions": [
    "user.profile.read",
    "user.location"
  ],
  "size_bytes": 102400,
  "developer": {
    "name": "Developer Name",
    "website": "https://example.com"
  }
}
```

## JS Bridge API

The host injects a `window.TinTin` object into every mini-app WebView. All calls are asynchronous and return Promises.

### User API

```typescript
namespace TinTin.user {
  /** Get the current user's profile (requires user.profile.read permission). */
  function getProfile(): Promise<UserProfile>;

  /** Get the current user's language/locale. */
  function getLanguage(): Promise<string>;
}

interface UserProfile {
  id: string;
  displayName: string;
  avatarUrl: string;        // data: URI or file://
  language: string;
}
```

### Messaging API

```typescript
namespace TinTin.message {
  /** Send a message from the mini-app to a chat (user or group). */
  function send(targetId: string, text: string): Promise<MessageResult>;

  /** Share content to a chat (opens native picker). */
  function share(text: string, dataUrl?: string): Promise<void>;
}

interface MessageResult {
  messageId: string;
  timestamp: number;
}
```

### Media API

```typescript
namespace TinTin.media {
  /** Pick an image from the gallery (returns data: URI). */
  function pickImage(): Promise<string>;

  /** Take a photo with the camera. */
  function takePhoto(): Promise<string>;

  /** Play a sound/audio file. */
  function playAudio(dataUri: string): Promise<void>;

  /** Vibrate the device. */
  function vibrate(pattern: number[]): Promise<void>;
}
```

### Storage API

```typescript
namespace TinTin.storage {
  /** Store a key-value pair (scoped to this mini-app). */
  function set(key: string, value: string): Promise<void>;

  /** Retrieve a stored value. */
  function get(key: string): Promise<string | null>;

  /** Remove a stored key. */
  function remove(key: string): Promise<void>;

  /** Clear all data for this mini-app. */
  function clear(): Promise<void>;
}
```

### UI API

```typescript
namespace TinTin.ui {
  /** Show a toast notification. */
  function toast(message: string, duration?: 'short' | 'long'): Promise<void>;

  /** Show a loading indicator. */
  function showLoading(): Promise<void>;

  /** Hide the loading indicator. */
  function hideLoading(): Promise<void>;

  /** Show a confirmation dialog. */
  function confirm(title: string, message: string): Promise<boolean>;

  /** Set the WebView navigation bar title. */
  function setTitle(title: string): Promise<void>;
}
```

### Payment API *(future)*

```typescript
namespace TinTin.payment {
  /** Create a payment request. */
  function createOrder(amount: number, currency: string, description: string): Promise<OrderResult>;

  /** Get payment status. */
  function getOrderStatus(orderId: string): Promise<OrderStatus>;
}

interface OrderResult {
  orderId: string;
  status: 'pending' | 'completed' | 'failed';
}

interface OrderStatus {
  orderId: string;
  status: 'pending' | 'completed' | 'failed';
  paidAt?: number;
}
```

### Network API *(restricted)*

```typescript
namespace TinTin.network {
  /** HTTP GET request (only to whitelisted domains from manifest). */
  function get(url: string): Promise<HttpResponse>;

  /** HTTP POST request. */
  function post(url: string, body: string, contentType?: string): Promise<HttpResponse>;
}

interface HttpResponse {
  status: number;
  body: string;
  headers: Record<string, string>;
}
```

## Security & Sandbox

### WebView Sandbox Rules

1. **No JavaScript `eval()`** — Content Security Policy (CSP) forbids `unsafe-eval`.
2. **No inline scripts** — All JS must be in external `.js` files.
3. **No direct network access** — All HTTP requests go through `TinTin.network.get/post` which enforces domain allowlists.
4. **No file system access** — Mini-apps cannot read/write the device file system.
5. **No iframes** — Embedding external content is forbidden.
6. **Storage isolation** — `TinTin.storage` is scoped per app_id.
7. **Message sending requires explicit user confirmation** — Each `TinTin.message.send()` call shows a confirmation dialog.
8. **Media permissions require runtime user consent** — Camera/gallery access prompts the user.

### CSP Header

```
default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';
img-src 'self' data:; connect-src 'none'; frame-src 'none';
```

### Size Limits

| Resource | Limit |
|----------|-------|
| Package size | 5 MB |
| Storage per app | 10 MB |
| `TinTin.storage` value length | 64 KB |
| HTTP response body | 1 MB |
| Message text length | 4096 chars |

## SDK Runtime (Rust Crate: `tintin-sdk`)

The `tintin-sdk` crate provides:

- `MiniAppManifest` — parsed manifest representation
- `MiniAppPackage` — .tma file reader/validator
- `PermissionSet` — permission checking
- `JsBridgeRequest` / `JsBridgeResponse` — typed message types for the JS bridge
- `SandboxConfig` — WebView configuration builder

See `tintin-sdk/src/lib.rs` for the full API.

## Host Integration

### iOS (WKWebView)

```swift
// TinTinHostBridge.swift
let config = WKWebViewConfiguration()
let bridge = TinTinScriptMessageHandler()
config.userContentController.add(bridge, name: "tintinBridge")

let webView = WKWebView(frame: .zero, configuration: config)
webView.loadFileURL(entryUrl, allowingReadAccessTo: appDirectory)
```

### Android (WebView)

```kotlin
// TinTinHostBridge.kt
val webView = WebView(context)
webView.settings.javaScriptEnabled = true
webView.addJavascriptInterface(TinTinBridge(context), "TinTin")
webView.loadUrl("file:///$appDir/index.html")
```

### Message Bridge Protocol

Communication uses `window.webkit.messageHandlers.tintinBridge.postMessage()` (iOS) and `TinTinBridge.onMessage()` (Android) under the hood. The `tintin-sdk` runtime normalizes this into a common request/response format:

**Request (mini-app → host):**
```json
{
  "id": "req_1234",
  "method": "user.getProfile",
  "params": {}
}
```

**Response (host → mini-app):**
```json
{
  "id": "req_1234",
  "result": { "id": "...", "displayName": "...", ... }
}
```

**Error:**
```json
{
  "id": "req_1234",
  "error": { "code": -1, "message": "Permission denied" }
}
```

## Future Work

- **Mini-app store** — Directory of published mini-apps with ratings
- **Mini-app payments** — In-app purchases through TinTin Pay
- **Mini-app sharing** — Share mini-app state via deep links
- **Mini-app analytics** — Usage analytics for developers
- **Mini-app debugging** — Remote debugging tools for development
- **Mini-app updates** — Auto-update mechanism for installed mini-apps
