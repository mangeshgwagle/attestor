# Attestor 4.1.3 for VS Code

This dependency-free local extension starts Attestor's bundled LSP 3.18 server for
supported source files. It applies UTF-16-correct incremental buffer changes,
publishes bounded diagnostics, scans every declared workspace root, and shows
content-addressed evidence on hover.

The 4.1.3 presentation remains a read-only editor surface. Defensive-security
posture, one-use authorization, and static attack-surface evidence stay behind
their bounded server/orchestrator contracts; the extension does not turn those
capabilities into automatic execution or source changes.

Workspace diagnostics are cancellable and report progress. Quick fixes never
carry an edit: after explicit modal consent, Attestor can return a verified
`WorkspaceEdit` inside a preview-only response. The extension opens its text in
a virtual document and never calls `workspace.applyEdit` or writes source.

The extension requires VS Code Workspace Trust. It never applies an edit,
never invokes a shell, and launches Python in isolated mode with Python path
injection variables removed. Set `attestor.pythonPath` if `python` is not on PATH.
Before launch, its integrity check validates the allowlisted bundled server files against the
SHA-256 inventory shipped inside the extension. A missing, unexpected, linked,
or modified server file makes startup fail closed.

For local development, open this directory in VS Code and press `F5`, or package
it with the official VS Code extension tooling. Run `npm run stage-server` after
changing the live server. The `vscode:prepublish` hook also stages the allowlisted
server automatically, so an installed VSIX is self-contained and never depends
on a repository-relative source directory outside the extension.

This local/private package is marked `UNLICENSED`; no license grant is implied.
