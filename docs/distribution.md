# MynaAuth の配布・インストール

Windows 11 x64 向けの開発版です。実ログオンの検証状況は [Windows ログイン手順](https://github.com/Himeyama/MynaAuth/blob/main/docs/windows-logon.md) を確認してください。オンライン失効確認は未実装です。

## 利用する方へ

[GitHub Releases](https://github.com/Himeyama/MynaAuth/releases) の Assets から配布用 ZIP をダウンロードして展開し、`MynaAuth-<バージョン>-win-x64-Setup.exe` を実行します。セットアップ EXE と SHA-256 も同じ Release に添付します。配布時は生成先フォルダー全体を ZIP にまとめ、EXE の名前を変更しないでください。署名は付いていません。チェックサムは破損検出用で、発行元を証明するものではありません。

Windows 標準の tar が LZMA2 の展開に対応している必要があります。.NET ランタイムは同梱します。実カードには別途、公式の64-bit JPKI 利用者ソフトと対応リーダーのドライバーが必要です。JPKI のソフトや利用者の証明書は再配布しません。

1. セットアップで設定アプリ一式を配置します。既定の配置先は `%ProgramFiles%\MynaAuth\app` です。
2. スタートメニューの MynaAuth を開き、Windows アカウント、カード／スマホの登録を済ませてから「ログイン画面へ追加」を実行します。この段階で専用の `%ProgramFiles%\MynaAuthSignIn` へ配置され、ログイン機能が有効になります。

PIN や Windows パスワードは設定アプリだけに入力してください。Windows 標準のサインイン手段は維持します。詳細は上記の Windows ログイン手順を参照してください。

## 解除・削除・更新

Windows のアプリ一覧からのアンインストールは、設定アプリ一式を削除します。**有効化済みのログイン機能と保護された登録情報は残ります。** ログイン機能も解除する場合は、先に標準の方法でサインインして、管理者の64-bit Windows PowerShell で実行してください。

```powershell
& "$env:ProgramFiles\MynaAuthSignIn\Uninstall-LogonProvider.ps1" -RemoveEnrollment
```

ログイン画面が DLL を使用中の場合があるため、ログイン用ファイルは残します。復旧アカウントも自動削除しません。更新時は新しいインストーラーを実行した後、設定アプリから登録を進めてください。既存のログイン機能を検出すると、読み込み中の DLL を上書きしない更新処理へ自動で切り替わります。手動では配置先の `Update-LogonProvider.ps1 -BundlePath <新しい app フォルダー>` を管理者として実行できます。詳しくは Windows ログイン手順を参照してください。

## 開発者向けビルド

.NET 9 SDK（設定アプリの標準 WPF Fluent テーマ用）と .NET 8 SDK、Visual Studio 2022 の C++ ビルドツール、CMake、NuGet 接続が必要です。[HSIS v0.8.3](https://github.com/Himeyama/hsis/tree/v0.8.3) の CLI を次のように発行し、`hsis.exe` と `Template` を一緒に保持します。アイコンは CLI のテンプレートに含まれるため、手動コピーは不要です。

```powershell
git clone --depth 1 --branch v0.8.3 https://github.com/Himeyama/hsis.git C:\path\to\hsis
dotnet publish C:\path\to\hsis\src\Hsis.Cli\Hsis.Cli.csproj -c Release -r win-x64 --self-contained true -o C:\path\to\hsis-cli
```

```powershell
$env:HSIS_7ZIP_PATH = 'C:\Program Files\7-Zip\7z.exe'
./scripts/Build-Installer.ps1 -HsisPath C:\path\to\hsis-cli\hsis.exe
```

`Directory.Build.props` がアプリのバージョンの基準です。成果物と SHA-256 は `artifacts/installer-<識別子>/Setup-*/` に生成されます。

GitHub では Actions の手動実行、またはバージョンと一致する `v0.1.0` 形式のタグの push で同じビルドを行います。タグのビルド・検証に成功すると、そのタグの GitHub Release を自動作成し、配布用 ZIP・セットアップ EXE・SHA-256 を添付します。同じワークフローの再実行では添付ファイルを更新します。ブランチを選んだ手動実行では Release を作成しません。結果は Actions の Artifacts にも30日間保存します。リポジトリにはソースだけを push し、`artifacts`、キャプチャー、ログ、個人の登録情報を含めません。

## バージョンとコミット

初版は `v0.1.0`。コミットごとに `Directory.Build.props` のアプリバージョンを更新し、同じ番号の注釈付きタグを作成します。機能追加はマイナー、バグ・セキュリティ修正やリファクタリング、文書・開発設定の変更はパッチを AI が自律的に更新します。メジャーは開発者の明示指示がある場合だけ更新します。

変更をファイル名を指定してステージしてから実行してください。バージョンと変更履歴のファイルはスクリプトが更新・ステージします。

```powershell
./version.ps1 -Part patch -Message 'fix: 修正内容' -Summary '変更履歴に記載する内容' -WhatIf
./version.ps1 -Part patch -Message 'fix: 修正内容' -Summary '変更履歴に記載する内容' -Push
```

`-Push` はブランチと作成したタグを一緒に push します。タグ push が配布ワークフローを起動します。機能追加は `-Part minor` を使います。`-Push` を省略した場合も、後で push するときは対応タグを必ず含めてください。失敗時は更新済みのバージョンのまま原因を解消し、再実行による余分なバージョン更新や既存タグの付け替えを避けてください。
