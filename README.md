# pxproxy

**Rust で実装した高速なローカル Proxy**

ブラウザなどの HTTP / HTTPS 通信を手元で中継・記録し、閲覧・編集・再送できる診断用プロキシです。
GUI アプリ（`pxproxy`）と、GUI なしで動くコマンド（`pxproxy-cli`）があります。

## 特徴

- **HTTPS を復号して記録**: ローカル CA が接続先ごとに証明書を発行し、通信内容をそのまま確認できます。
- **ヘッダを書き換えない**: 自前の HTTP/1.x 実装で、ヘッダの大文字小文字・順序・重複を変えずに転送します。
- **速さを優先した設計**
  - tokio による非同期 I/O。接続ごとに独立して処理し、Intercept で止めた通信が他の通信を待たせません。
  - サーバ証明書の鍵を全ホストで共有し、発行した証明書はキャッシュします（ホストごとの鍵生成を省きます）。
  - 記録は専用スレッドへキューで渡し、まとめてトランザクションでコミットします。プロキシは DB への書き込みを待ちません。
  - Body は読んだそばからクライアントへ流します（Intercept で止める通信を除く）。大きなダウンロードや SSE も溜めずに届きます。
  - SQLite（WAL）にメタデータを保存します。大きな Body は blake3 で重複を除いたうえで zstd 圧縮して保存します。
- **案件単位で管理**: 1 案件 = 1 フォルダ。zip にまとめて受け渡しできます。

## 機能

| 画面 | できること |
|---|---|
| History | 記録した通信の一覧と詳細。日時、ホスト / パス、種類（HTML・XHR・JS・CSS・画像など）、ステータス、診断対象で絞り込めます。「メモ」列のダブルクリックで行ごとにメモを残せます |
| 詳細表示 | JSON / HTML / XML の整形とシンタックスハイライト、Request / Response 内の検索、画像のプレビュー、gzip / br / zstd / deflate の展開。WebSocket に切り替わった通信は、送受信したメッセージを一覧できます |
| サイトマップ | 記録した通信をホスト → パスのツリーで表示します。ノードを選ぶと、その配下の通信だけを一覧します |
| Intercept | ルールに一致したリクエスト / レスポンスを止めて、編集・Forward・Drop できます |
| Repeater | リクエストを編集して何度でも送り直せます。送った内容と結果は ◀ ▶ で行き来できます |
| Comparer | 2 つの通信のリクエスト / レスポンスを左右に並べ、行と単語の単位で差分を表示します（History などで右クリック →「Comparer に送る」） |
| 検出 | 記録した通信を調べるだけのパッシブチェックです。セキュリティヘッダの欠落、Cookie の属性、エラーメッセージ・SQL エラーの露出、URL 内の機密らしきパラメータ、CORS の設定、内部 IP の露出などを、チェックとホストでまとめて表示します |
| 診断対象 / ルール | 診断対象（Scope）のホスト・パス、Intercept の条件、上流プロキシ、TLS パススルー、記録する Body の上限を案件ごとに設定します |
| 上流プロキシ | 社内プロキシなどを経由して接続します（HTTPS は CONNECT、平文 HTTP は absolute-form、Basic 認証、直接つなぐホストの指定）。Repeater と `pxproxy-cli run` にも適用されます |
| TLS パススルー | 指定したホスト（ワイルドカード可）の HTTPS は復号せずにそのまま中継します。証明書ピンニングで失敗するアプリや、診断対象外の通信に使います |
| 透過プロキシ | プロキシ設定のできないアプリの通信も、iptables などで待受へ転送すれば記録できます（下記） |
| ダミーサーバ | 任意のドメインに、パスごとのステータス・ヘッダ・Body と受け付けるメソッドを設定した仮想 Web サーバを用意します（`/` は必須）。応答には `{{query.q}}`・`{{form.name}}`・`{{json.a.b}}`・`{{header.名前}}` などでリクエストの内容を埋め込めます（`{{html:…}}` で HTML エスケープ）。プロキシに届いた通信のうちホスト名が一致するものには上流へ接続せずに応答します（待受は増やさず、HTTP / HTTPS・ポートは問いません）。Repeater と `pxproxy-cli run` にも適用されます |
| hosts | hosts ファイルと同じ書式（`IP ホスト名…`、ワイルドカード可）で接続先の IP を案件ごとに上書きします。Host ヘッダ・SNI は元のまま。Repeater と `pxproxy-cli run` にも適用されます |
| エンコード / デコード | URL・Base64・HTML エンティティ・Hex・Unicode エスケープの変換と、JWT のデコード |

## 必要なもの

- Rust 1.88 以降（edition 2024）
- Windows（動作確認済み）。macOS / Linux でもビルドできる構成ですが、動作は未確認です

## ビルド

```sh
cargo build --release
```

`target/release/` に次の 2 つができます。

- `pxproxy`（Windows は `pxproxy.exe`）: GUI アプリ
- `pxproxy-cli`: GUI なしのコマンド

## はじめかた

1. `pxproxy` を起動し、「新規案件を作成」で案件を作ります（空のフォルダを「案件を開く」で選んでも、そのフォルダが新しい案件になります）。
2. 「▶ プロキシ開始」を押します（既定の待受は `127.0.0.1:8080`）。
3. ブラウザまたは OS のプロキシ設定を `127.0.0.1:8080` にします。
4. HTTPS を記録するには、CA 証明書を信頼済みのルート証明機関として登録します（下記）。
5. 通信すると History に記録されます。

### CA 証明書の登録

CA は初回起動時に自動で作られ、次の場所に保存されます。

- Windows: `%APPDATA%\pxproxy\ca.crt`
- その他: `$XDG_CONFIG_HOME/pxproxy/ca.crt`（`XDG_CONFIG_HOME` が未設定なら、カレントディレクトリの `pxproxy/ca.crt`）

メニューの「CA → CA 証明書を保存…」、または `pxproxy-cli ca -o pxproxy-ca.crt` で書き出し、
OS（またはブラウザ）の「信頼されたルート証明機関」に登録してください。

> [!WARNING]
> `ca.key` を持つ人は、この CA を信頼した端末の HTTPS 通信を偽装できます。`ca.key` は共有しないでください。
> 診断が終わったら、登録した CA を削除することをおすすめします。

### 透過プロキシ

プロキシ設定のできないアプリの通信は、iptables などで宛先を pxproxy の待受（例: `127.0.0.1:8080`）へ転送して記録します。
待受に CONNECT 無しで届いた通信は、次のように宛先を判断して中継します。通常のプロキシ要求と同じ待受で受け付け、モードの切り替えはありません。

- 平文 HTTP: `Host` ヘッダのホスト・ポート（ポート省略時は 80）
- HTTPS: TLS の SNI で証明書を発行し、`Host` ヘッダのホスト・ポート（ポート省略時は 443）へ転送します。`Host` が無ければ SNI を使います

pxproxy 自身から上流への通信が同じ転送ルールに掛かると無限ループになるため、転送の対象から除外してください
（iptables の `-m owner ! --uid-owner` など）。上流が pxproxy の待受そのものに解決される場合は、502 とエラーを返して記録します。
## キーボードショートカット

| キー | 画面 | 動作 |
|---|---|---|
| ↑ / ↓ | History / サイトマップ | 行を移動 |
| Ctrl+F | History / サイトマップ / 検出 | 詳細の検索欄へ（Enter で次、Shift+Enter で前） |
| Ctrl+R | History / サイトマップ / 検出 / Intercept | 選択中のリクエストを Repeater に送る |
| Ctrl+F / Ctrl+D | Intercept | Forward / Drop |
| Ctrl+Enter | Repeater | 送信 |
| Alt+← / Alt+→ | Repeater | 前 / 次に送った内容へ |

## コマンドラインからの起動

### GUI（pxproxy）

```sh
pxproxy [案件フォルダ] [オプション]
```

| オプション | 説明 |
|---|---|
| `案件フォルダ` | 起動時に開く案件。無ければ作成します |
| `-l, --listen <アドレス>` | 待受アドレス（既定: `127.0.0.1:8080`） |
| `-s, --start` | 起動と同時にプロキシを開始します（案件の指定が必要） |
| `-h, --help` / `-V, --version` | 説明 / バージョンを表示します |

```sh
# 案件を開いて、すぐ 8888 番で記録を始める
pxproxy ./webapp.pxproj --listen 127.0.0.1:8888 --start
```

### GUI なし（pxproxy-cli）

```sh
pxproxy-cli run <案件フォルダ> [-l <アドレス>] [--create] [-q]   # 記録しながら待ち受け（Ctrl+C で終了）
pxproxy-cli export <案件フォルダ> <出力.zip>                    # 案件を zip にまとめる
pxproxy-cli import <入力.zip> <展開先フォルダ>                  # zip を案件フォルダに展開する
pxproxy-cli ca [-o <ファイル>]                                  # CA 証明書 (PEM) を表示 / 保存
```

`run` は通信ごとに 1 行ずつ標準出力に表示します（`-q` で表示しません）。

```text
$ pxproxy-cli run ./webapp.pxproj --create
pxproxy-cli: 127.0.0.1:8080 で待ち受け中（Ctrl+C で終了）
200 GET     https://example.com/  42 ms  1.2K
404 GET     https://example.com/missing  18 ms  335B
```

記録した案件は、あとから GUI で開いて閲覧できます。CA は GUI と共通です。
同じ案件を GUI と `pxproxy-cli run` で同時に開かないでください。

## 案件フォルダ

```text
<name>.pxproj/
├─ project.toml      フォーマットのバージョンなど
├─ settings.toml     診断対象 / Intercept のルール / hosts
├─ project.sqlite    通信のメタデータ（WAL）
└─ bodies/ab/cd/<blake3>.zst   大きな Body（zstd 圧縮、内容のハッシュで重複を除く）
```

パスはすべて相対なので、フォルダごとコピーしても、zip にまとめても移動できます。
zip のエクスポート / インポートはバックグラウンドで実行し、途中で中止できます。

## 構成

| クレート | 役割 |
|---|---|
| `crates/px-proxy` | MITM プロキシ本体（HTTP/1.x、TLS、CA、Intercept、Repeater の送信） |
| `crates/px-store` | 案件の保存（SQLite + Body ストア、zip の入出力） |
| `crates/px-app` | GUI（egui / eframe）。バイナリ名は `pxproxy` |
| `crates/px-cli` | GUI なしのコマンド。バイナリ名は `pxproxy-cli` |

## 制限事項

- HTTP/2 には対応していません（ALPN で HTTP/1.1 を使います）。
- 透過プロキシは宛先を `Host` / SNI で判断します。元の宛先アドレスを OS から取得する方式（Linux の `SO_ORIGINAL_DST` など）には対応していません。SNI の無い TLS は中継できません。
- WebSocket は記録と表示のみで、メッセージの Intercept・再送はできません。
- 記録する Body の上限（既定 32 MB）を超えた分は記録しません。Intercept で止める通信は Body 全体をメモリ上で扱います。
- パッシブチェックは、この機能より前に記録した通信も案件を開いたときにバックグラウンドで順に調べます（「検出」タブの「再スキャン」でやり直せます）。
- Repeater のタブは保存されません（送った通信は History に残ります）。

## 開発

```sh
cargo test --workspace
cargo clippy --workspace --all-targets
```
