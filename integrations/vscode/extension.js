'use strict';

const vscode = require('vscode');
const cp = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const MAX_MESSAGE_BYTES = 4 * 1024 * 1024;
const REQUEST_TIMEOUT_MS = 15000;
const CLIENT_VERSION = '4.1.3';
const DIAGNOSTIC_SOURCE = 'Attestor 4.1.3';
const SERVER_BUNDLE_SCHEMA = 'attestor-vscode-server-bundle/1.0';
const SERVER_BUNDLE_FILES = new Set([
  'advanced_rules.py', 'deepscan.py', 'detect.py', 'multilang.py',
  'nativepool.py', 'nativescan.py', 'attestor_lsp.py', 'attestor_lsp41.py', 'patchguard.py',
  'polyglot.py', 'precision_catalog.py', 'rarebugs.py', 'runtime_lab.py',
  'scanengine.py', 'verified_remediation.py'
]);
const PYTHON_BOOTSTRAP = [
  'import runpy,sys',
  'd,p,*a=sys.argv[1:]',
  'sys.path.insert(0,d)',
  'sys.argv=[p,*a]',
  "runpy.run_path(p,run_name='__main__')"
].join(';');
const SUPPORTED = new Set([
  'python', 'javascript', 'javascriptreact', 'typescript', 'typescriptreact',
  'c', 'cpp', 'haskell', 'rust', 'go', 'java', 'csharp', 'php', 'ruby', 'shellscript'
]);

function safeEnvironment() {
  const blocked = new Set(['PYTHONPATH', 'PYTHONHOME', 'PYTHONSTARTUP', 'PYTHONINSPECT']);
  const env = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (!blocked.has(key.toUpperCase()) && typeof value === 'string') env[key] = value;
  }
  env.PYTHONNOUSERSITE = '1';
  env.PYTHONDONTWRITEBYTECODE = '1';
  env.PYTHONUTF8 = '1';
  return env;
}

function verifiedBundledServer(extensionPath) {
  const extensionRoot = path.resolve(extensionPath);
  const serverRoot = path.resolve(extensionRoot, 'server');
  if (path.dirname(serverRoot) !== extensionRoot) {
    throw new Error('Attestor bundled server path is invalid.');
  }
  try {
    const serverStat = fs.lstatSync(serverRoot);
    if (!serverStat.isDirectory() || serverStat.isSymbolicLink()) {
      throw new Error('invalid server directory');
    }
    const expectedEntries = new Set([...SERVER_BUNDLE_FILES, 'server-manifest.json']);
    const actualEntries = fs.readdirSync(serverRoot);
    if (actualEntries.length !== expectedEntries.size ||
        actualEntries.some(name => !expectedEntries.has(name))) {
      throw new Error('unexpected server bundle entry');
    }
    const manifestPath = path.join(serverRoot, 'server-manifest.json');
    const manifestStat = fs.lstatSync(manifestPath);
    if (!manifestStat.isFile() || manifestStat.isSymbolicLink() || manifestStat.size > 64 * 1024) {
      throw new Error('invalid manifest');
    }
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    if (manifest.schema !== SERVER_BUNDLE_SCHEMA || manifest.version !== CLIENT_VERSION ||
        manifest.entrypoint !== 'attestor_lsp41.py' || !Array.isArray(manifest.files) ||
        manifest.files.length !== SERVER_BUNDLE_FILES.size) {
      throw new Error('invalid bundle identity');
    }
    const seen = new Set();
    for (const item of manifest.files) {
      if (!item || typeof item.path !== 'string' || !SERVER_BUNDLE_FILES.has(item.path) ||
          seen.has(item.path) || !/^[a-f0-9]{64}$/.test(item.sha256) ||
          !Number.isSafeInteger(item.size) || item.size < 1 || item.size > 2 * 1024 * 1024) {
        throw new Error('invalid bundle entry');
      }
      const candidate = path.resolve(serverRoot, item.path);
      if (path.dirname(candidate) !== serverRoot) throw new Error('escaped bundle path');
      const stat = fs.lstatSync(candidate);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.size !== item.size) {
        throw new Error('invalid bundled file');
      }
      const actual = crypto.createHash('sha256').update(fs.readFileSync(candidate)).digest();
      const expected = Buffer.from(item.sha256, 'hex');
      if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) {
        throw new Error('bundle digest mismatch');
      }
      seen.add(item.path);
    }
    if (seen.size !== SERVER_BUNDLE_FILES.size) throw new Error('incomplete bundle');
    return path.join(serverRoot, manifest.entrypoint);
  } catch (_) {
    throw new Error('Attestor bundled server failed integrity verification.');
  }
}

class LspConnection {
  constructor(serverPath, pythonPath, output, onNotification, onExit) {
    this.output = output;
    this.onNotification = onNotification;
    this.onExit = onExit;
    this.pending = new Map();
    this.nextId = 1;
    this.buffer = Buffer.alloc(0);
    this.closed = false;
    this.process = cp.spawn(
      pythonPath,
      ['-I', '-B', '-X', 'utf8', '-c', PYTHON_BOOTSTRAP,
        path.dirname(serverPath), serverPath],
      { cwd: path.dirname(serverPath), env: safeEnvironment(), shell: false,
        stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true }
    );
    this.process.stdout.on('data', chunk => this.consume(chunk));
    this.process.stderr.on('data', chunk => {
      const text = chunk.toString('utf8').slice(0, 4000).trim();
      if (text) this.output.appendLine(`[server] ${text}`);
    });
    this.process.on('error', error => this.failAll(`server start failed: ${error.name}`));
    this.process.on('exit', code => {
      this.closed = true;
      this.failAll(`server exited (${code === null ? 'terminated' : code})`);
      this.onExit();
    });
  }

  consume(chunk) {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    while (this.buffer.length) {
      const boundary = this.buffer.indexOf('\r\n\r\n');
      if (boundary < 0) {
        if (this.buffer.length > 65536) this.abort('oversized LSP header');
        return;
      }
      const header = this.buffer.subarray(0, boundary).toString('ascii');
      const match = /(?:^|\r\n)Content-Length:\s*(\d+)\s*(?:\r\n|$)/i.exec(header);
      if (!match) return this.abort('missing LSP Content-Length');
      const length = Number(match[1]);
      if (!Number.isSafeInteger(length) || length < 0 || length > MAX_MESSAGE_BYTES) {
        return this.abort('invalid LSP message boundary');
      }
      const end = boundary + 4 + length;
      if (this.buffer.length < end) return;
      const body = this.buffer.subarray(boundary + 4, end);
      this.buffer = this.buffer.subarray(end);
      try {
        const message = JSON.parse(body.toString('utf8'));
        this.dispatch(message);
      } catch (_) {
        return this.abort('invalid LSP JSON response');
      }
    }
  }

  dispatch(message) {
    if (Object.prototype.hasOwnProperty.call(message, 'id')) {
      const item = this.pending.get(message.id);
      if (!item) return;
      this.pending.delete(message.id);
      clearTimeout(item.timer);
      if (message.error) item.reject(new Error(String(message.error.message || 'LSP error')));
      else item.resolve(message.result);
    } else if (typeof message.method === 'string') {
      this.onNotification(message.method, message.params || {});
    }
  }

  send(message) {
    if (this.closed || !this.process.stdin.writable) throw new Error('Attestor server is unavailable');
    const body = Buffer.from(JSON.stringify(message), 'utf8');
    if (body.length > MAX_MESSAGE_BYTES) throw new Error('LSP request exceeds 4 MiB');
    this.process.stdin.write(Buffer.concat([
      Buffer.from(`Content-Length: ${body.length}\r\n\r\n`, 'ascii'), body
    ]));
  }

  notify(method, params) {
    this.send({ jsonrpc: '2.0', method, params });
  }

  request(method, params) {
    const id = this.nextId++;
    const pending = new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`Attestor request timed out: ${method}`));
      }, REQUEST_TIMEOUT_MS);
      this.pending.set(id, { resolve, reject, timer });
      try {
        this.send({ jsonrpc: '2.0', id, method, params });
      } catch (error) {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(error);
      }
    });
    pending.requestId = id;
    return pending;
  }

  cancel(requestId) {
    if (this.pending.has(requestId)) this.notify('$/cancelRequest', { id: requestId });
  }

  failAll(reason) {
    for (const item of this.pending.values()) {
      clearTimeout(item.timer);
      item.reject(new Error(reason));
    }
    this.pending.clear();
  }

  abort(reason) {
    this.output.appendLine(`[protocol] ${reason}`);
    this.dispose();
  }

  async dispose() {
    if (this.closed) return;
    try {
      await Promise.race([
        this.request('shutdown', null),
        new Promise(resolve => setTimeout(resolve, 400))
      ]);
      if (!this.closed) this.notify('exit', null);
    } catch (_) {
      // The process is still terminated below; disposal must be bounded.
    }
    this.closed = true;
    this.failAll('Attestor server stopped');
    setTimeout(() => {
      if (this.process && !this.process.killed) this.process.kill();
    }, 100);
  }
}

class ImprovementProvider {
  constructor() {
    this.content = new Map();
  }
  provideTextDocumentContent(uri) {
    return this.content.get(uri.toString()) || 'No verified improvement is available.';
  }
  put(language, text) {
    const nonce = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
    const uri = vscode.Uri.parse(`attestor-improvement:${nonce}.attestor.${language || 'txt'}`);
    this.content.set(uri.toString(), text);
    return uri;
  }
}

let connection = null;
let initialized = false;
let contextRef = null;
let diagnostics = null;
let output = null;
let provider = null;
const progressReporters = new Map();

function documentUri(document) {
  return document.uri.toString();
}

function workspaceFolders() {
  return (vscode.workspace.workspaceFolders || []).map(folder => ({
    uri: folder.uri.toString(), name: folder.name
  }));
}

function publishDiagnostics(params) {
  if (!params || typeof params.uri !== 'string' || !Array.isArray(params.diagnostics)) return;
  let uri;
  try { uri = vscode.Uri.parse(params.uri); } catch (_) { return; }
  const rows = params.diagnostics.slice(0, 500).map(item => {
    const start = item.range && item.range.start || { line: 0, character: 0 };
    const end = item.range && item.range.end || { line: start.line, character: start.character + 1 };
    const range = new vscode.Range(start.line, start.character, end.line, end.character);
    const severity = item.severity === 1 ? vscode.DiagnosticSeverity.Error :
      item.severity === 2 ? vscode.DiagnosticSeverity.Warning :
      item.severity === 4 ? vscode.DiagnosticSeverity.Hint : vscode.DiagnosticSeverity.Information;
    const diagnostic = new vscode.Diagnostic(range, String(item.message || 'Attestor finding'), severity);
    diagnostic.source = typeof item.source === 'string' ? item.source.slice(0, 80) : DIAGNOSTIC_SOURCE;
    diagnostic.code = item.code;
    return diagnostic;
  });
  diagnostics.set(uri, rows);
}

function openDocument(document) {
  if (!connection || !initialized || !SUPPORTED.has(document.languageId)) return;
  connection.notify('textDocument/didOpen', {
    textDocument: {
      uri: documentUri(document), languageId: document.languageId,
      version: document.version, text: document.getText()
    }
  });
}

async function startServer() {
  if (connection && initialized) return connection;
  if (!vscode.workspace.isTrusted) {
    throw new Error('Attestor requires Workspace Trust before starting a local analysis process.');
  }
  const serverPath = verifiedBundledServer(contextRef.extensionPath);
  const pythonPath = vscode.workspace.getConfiguration('attestor').get('pythonPath', 'python');
  connection = new LspConnection(serverPath, pythonPath, output, (method, params) => {
    if (method === 'textDocument/publishDiagnostics') publishDiagnostics(params);
    if (method === '$/progress' && params && progressReporters.has(params.token)) {
      const reporter = progressReporters.get(params.token); const value = params.value || {};
      if (value.kind === 'report') reporter.report({message: String(value.message || '')});
      if (value.kind === 'end') progressReporters.delete(params.token);
    }
  }, () => { initialized = false; connection = null; });
  const result = await connection.request('initialize', {
    processId: null, rootUri: null, workspaceFolders: workspaceFolders(),
    capabilities: {workspace: {workspaceFolders: true}, window: {workDoneProgress: true}},
    clientInfo: { name: 'Attestor VS Code', version: CLIENT_VERSION }
  });
  if (!result || !result.capabilities) throw new Error('Attestor returned an invalid initialize response.');
  const serverVersion = result.serverInfo && typeof result.serverInfo.version === 'string' ?
    result.serverInfo.version.slice(0, 40) : 'unknown';
  const compatibilityServer = /^(?:3\.(?:0|5)|4\.0)(?:\.|$)/.test(serverVersion);
  connection.notify('initialized', {});
  initialized = true;
  for (const document of vscode.workspace.textDocuments) openDocument(document);
  output.appendLine(`Attestor 4.1.3 live analysis started; connected to server ${serverVersion}` +
    (compatibilityServer ? ' (compatibility server).' : '.'));
  return connection;
}

async function previewImprovement() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) return vscode.window.showInformationMessage('Open a source file first.');
  try {
    const consent = await vscode.window.showWarningMessage(
      'Attestor will generate and verify a preview WorkspaceEdit. It will not apply or write it.',
      { modal: true }, 'Generate preview');
    if (consent !== 'Generate preview') return;
    const client = await startServer();
    const result = await client.request('attestor/previewWorkspaceEdit', {
      uri: documentUri(editor.document), consent: true
    });
    const changes = result && result.workspaceEdit && result.workspaceEdit.documentChanges;
    const edits = Array.isArray(changes) && changes[0] && Array.isArray(changes[0].edits) ? changes[0].edits : [];
    const improvedSource = edits[0] && typeof edits[0].newText === 'string' ? edits[0].newText : '';
    if (!result || result.accepted !== true || !result.available || !result.previewOnly || !improvedSource) {
      const reason = result && result.reason ? String(result.reason) : 'No supported verified change was found.';
      return vscode.window.showInformationMessage(`Attestor: ${reason}`);
    }
    const header = [
      'ATTESTOR 4.1.3 VERIFIED WORKSPACE EDIT PREVIEW',
      `Target: ${editor.document.fileName}`,
      `Accepted: ${result.accepted === true}`,
      `Consent recorded: ${result.consentRecorded === true}`,
      'This preview does not modify the workspace.', '',
      'FULL IMPROVED SOURCE', improvedSource
    ].join('\n');
    const uri = provider.put(editor.document.languageId, header);
    const document = await vscode.workspace.openTextDocument(uri);
    await vscode.window.showTextDocument(document, { preview: true, viewColumn: vscode.ViewColumn.Beside });
  } catch (error) {
    vscode.window.showErrorMessage(`Attestor preview failed safely: ${error.name || 'Error'}`);
  }
}

async function scanWorkspace() {
  const client = await startServer();
  return vscode.window.withProgress({location: vscode.ProgressLocation.Notification,
    title: 'Attestor 4.1.3 workspace diagnostics', cancellable: true}, async (reporter, cancellation) => {
    const workDoneToken = `attestor41-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    progressReporters.set(workDoneToken, reporter);
    const pending = client.request('workspace/diagnostic', {workDoneToken});
    const subscription = cancellation.onCancellationRequested(() => client.cancel(pending.requestId));
    try {
      const result = await pending;
      const items = result && Array.isArray(result.items) ? result.items : [];
      for (const item of items.slice(0, 500)) {
        publishDiagnostics({uri: item.uri, diagnostics: Array.isArray(item.items) ? item.items : []});
      }
      reporter.report({message: `${items.length} files analyzed`});
      return items.length;
    } finally {
      subscription.dispose(); progressReporters.delete(workDoneToken);
    }
  });
}

const documentSelector = [...SUPPORTED].map(language => ({language, scheme: 'file'}));

const hoverProvider = {
  async provideHover(document, position, cancellation) {
    try {
      const client = await startServer();
      const pending = client.request('textDocument/hover', {
        textDocument: {uri: documentUri(document)},
        position: {line: position.line, character: position.character}
      });
      const subscription = cancellation.onCancellationRequested(() => client.cancel(pending.requestId));
      try {
        const result = await pending;
        if (!result || !result.contents || typeof result.contents.value !== 'string') return null;
        const markdown = new vscode.MarkdownString(result.contents.value);
        markdown.isTrusted = false; markdown.supportHtml = false;
        const range = result.range ? new vscode.Range(
          result.range.start.line, result.range.start.character,
          result.range.end.line, result.range.end.character) : undefined;
        return new vscode.Hover(markdown, range);
      } finally { subscription.dispose(); }
    } catch (_) { return null; }
  }
};

const codeActionProvider = {
  provideCodeActions(_document, _range, context) {
    if (!context.diagnostics.some(item => String(item.source || '').startsWith('Attestor'))) return [];
    const action = new vscode.CodeAction('Attestor: preview verified WorkspaceEdit', vscode.CodeActionKind.QuickFix);
    action.command = {command: 'attestor.previewImprovement', title: 'Preview verified WorkspaceEdit'};
    action.isPreferred = false;
    return [action];
  }
};

function activate(context) {
  contextRef = context;
  diagnostics = vscode.languages.createDiagnosticCollection('attestor');
  output = vscode.window.createOutputChannel('Attestor 4.1.3');
  provider = new ImprovementProvider();
  context.subscriptions.push(
    diagnostics, output,
    vscode.workspace.registerTextDocumentContentProvider('attestor-improvement', provider),
    vscode.languages.registerHoverProvider(documentSelector, hoverProvider),
    vscode.languages.registerCodeActionsProvider(documentSelector, codeActionProvider,
      {providedCodeActionKinds: [vscode.CodeActionKind.QuickFix]}),
    vscode.commands.registerCommand('attestor.start', async () => {
      try { await startServer(); }
      catch (error) { vscode.window.showErrorMessage(`Attestor could not start: ${error.message}`); }
    }),
    vscode.commands.registerCommand('attestor.previewImprovement', previewImprovement),
    vscode.commands.registerCommand('attestor.scanWorkspace', async () => {
      try { await scanWorkspace(); }
      catch (error) { vscode.window.showErrorMessage(`Attestor workspace scan failed safely: ${error.message}`); }
    }),
    vscode.commands.registerCommand('attestor.restart', async () => {
      if (connection) await connection.dispose();
      connection = null; initialized = false; diagnostics.clear();
      try { await startServer(); }
      catch (error) { vscode.window.showErrorMessage(`Attestor could not restart: ${error.message}`); }
    }),
    vscode.workspace.onDidOpenTextDocument(openDocument),
    vscode.workspace.onDidChangeTextDocument(event => {
      if (!connection || !initialized || !SUPPORTED.has(event.document.languageId)) return;
      connection.notify('textDocument/didChange', {
        textDocument: { uri: documentUri(event.document), version: event.document.version },
        contentChanges: event.contentChanges.map(change => ({
          range: {start: {line: change.range.start.line, character: change.range.start.character},
                  end: {line: change.range.end.line, character: change.range.end.character}},
          rangeLength: change.rangeLength, text: change.text
        }))
      });
    }),
    vscode.workspace.onDidChangeWorkspaceFolders(event => {
      if (connection && initialized) connection.notify('workspace/didChangeWorkspaceFolders', {event: {
        added: event.added.map(folder => ({uri: folder.uri.toString(), name: folder.name})),
        removed: event.removed.map(folder => ({uri: folder.uri.toString(), name: folder.name}))
      }});
    }),
    vscode.workspace.onDidSaveTextDocument(document => {
      if (connection && initialized && SUPPORTED.has(document.languageId)) {
        connection.notify('textDocument/didSave', {
          textDocument: { uri: documentUri(document) }, text: document.getText()
        });
      }
    }),
    vscode.workspace.onDidCloseTextDocument(document => {
      if (connection && initialized) {
        connection.notify('textDocument/didClose', { textDocument: { uri: documentUri(document) } });
      }
      diagnostics.delete(document.uri);
    })
  );
  if (vscode.workspace.getConfiguration('attestor').get('enableOnStartup', true) &&
      vscode.workspace.isTrusted && vscode.window.activeTextEditor &&
      SUPPORTED.has(vscode.window.activeTextEditor.document.languageId)) {
    startServer().catch(error => output.appendLine(`Automatic start refused: ${error.name}`));
  }
}

async function deactivate() {
  if (connection) await connection.dispose();
  connection = null;
  initialized = false;
}

module.exports = { activate, deactivate, __test: { verifiedBundledServer } };
