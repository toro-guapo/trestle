import { spawnSync } from "child_process";
import { accessSync, chmodSync, constants, existsSync } from "fs";
import * as path from "path";
import * as vscode from "vscode";
import { Trace } from "vscode-jsonrpc";
import {
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
} from "vscode-languageclient/node";

let client: LanguageClient | undefined;
let output: vscode.OutputChannel | undefined;
let traceOutput: vscode.OutputChannel | undefined;
let extensionContext: vscode.ExtensionContext | undefined;

export function activate(context: vscode.ExtensionContext): void {
  extensionContext = context;
  output = vscode.window.createOutputChannel("Trestle");
  context.subscriptions.push(output);
  output.appendLine("Trestle extension activating.");

  const restart = async (reason: string): Promise<void> => {
    output?.appendLine(`Restarting language server: ${reason}.`);
    await stopClient();
    await startClient();
  };

  context.subscriptions.push(
    vscode.commands.registerCommand("trestle.restart", () =>
      restart("restart command invoked"),
    ),
  );

  context.subscriptions.push(
    vscode.workspace.onDidChangeWorkspaceFolders(() => {
      if (!client) {
        startClient();
      }
    }),
  );

  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration((event) => {
      if (event.affectsConfiguration("trestle.trace")) {
        restart("trace setting changed");
      }
    }),
  );

  context.subscriptions.push({ dispose: stopClient });

  startClient();
}

export async function deactivate(): Promise<void> {
  await stopClient();
}

function isTraceEnabled(): boolean {
  return vscode.workspace.getConfiguration("trestle").get("trace") === true;
}

function trace(message: string): void {
  if (isTraceEnabled()) {
    output?.appendLine(message);
  }
}

async function startClient(): Promise<void> {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) {
    output?.appendLine(
      "No workspace folder open. The language server will start when a folder is opened.",
    );
    return;
  }

  if (isTraceEnabled()) {
    const docs = vscode.workspace.textDocuments;
    trace(`Open documents at start: ${docs.length}.`);
    for (const doc of docs) {
      trace(`  ${doc.uri.toString()} (${doc.languageId}).`);
    }
  }

  const command = resolveCommand();
  const explainSupported = supportsExplain(command);
  trace(
    `Trestle ${explainSupported ? "supports" : "does not support"} '--explain'.`,
  );

  const workspacePaths = folders.map((f) => f.uri.fsPath);
  const args = ["lsp"];
  if (explainSupported) {
    args.push("--explain");
  }
  args.push(...workspacePaths);
  output?.appendLine(`Spawning: ${command} ${args.join(" ")}`);

  const serverOptions: ServerOptions = { command, args };

  const clientOptions: LanguageClientOptions = {
    documentSelector: [{ scheme: "file" }],
  };

  if (isTraceEnabled()) {
    if (!traceOutput) {
      traceOutput = vscode.window.createOutputChannel("Trestle Trace");
      extensionContext?.subscriptions.push(traceOutput);
    }
    clientOptions.traceOutputChannel = traceOutput;
  }

  client = new LanguageClient(
    "trestle",
    "Trestle Language Server",
    serverOptions,
    clientOptions,
  );

  try {
    await client.start();
    output?.appendLine("Language server started.");
    if (isTraceEnabled()) {
      await client.setTrace(Trace.Verbose);
    }
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    output?.appendLine(`Failed to start language server: ${detail}`);
    vscode.window.showErrorMessage(
      `Trestle: failed to start language server (${command}). ${detail}`,
    );
    client = undefined;
  }
}

function resolveCommand(): string {
  const configured = readConfiguredPath();
  if (configured) {
    output?.appendLine(
      `Using trestle from 'trestle.path' setting: ${configured}.`,
    );
    return configured;
  }

  const onPath = findOnPath();
  if (onPath) {
    output?.appendLine(`Using trestle found on PATH: ${onPath}.`);
    return onPath;
  }

  const bundled = findBundled();
  if (bundled) {
    output?.appendLine(`Using trestle bundled with the extension: ${bundled}.`);
    return bundled;
  }

  output?.appendLine(
    "Could not locate a trestle executable. Set 'trestle.path' to the path of the trestle binary or ensure it is on your system PATH.",
  );

  return "trestle";
}

function supportsExplain(command: string): boolean {
  const result = spawnSync(command, ["--help"], { encoding: "utf8" });

  if (result.error || result.status !== 0) {
    const detail = result.error
      ? result.error.message
      : `exit code ${result.status}`;

    output?.appendLine(
      `Could not read trestle --help to probe for '--explain' support: ${detail}.`,
    );

    return false;
  }

  return /--explain\b/.test(result.stdout);
}

function readConfiguredPath(): string | undefined {
  const raw: unknown = vscode.workspace.getConfiguration("trestle").get("path");
  if (raw === undefined || raw === null) {
    return undefined;
  }

  if (typeof raw !== "string") {
    output?.appendLine(
      `Ignoring 'trestle.path' setting because it is not a string (got ${typeof raw}).`,
    );
    return undefined;
  }

  const trimmed = raw.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function findOnPath(): string | undefined {
  const lookup = process.platform === "win32" ? "where" : "which";
  const result = spawnSync(lookup, ["trestle"], { encoding: "utf8" });

  if (result.error || result.status !== 0) {
    return undefined;
  }

  const first = result.stdout.split(/\r?\n/)[0]?.trim();
  if (!first || first.length === 0) {
    return undefined;
  }

  try {
    accessSync(first, constants.X_OK);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    output?.appendLine(
      `'${lookup} trestle' reported '${first}' but it is not an executable file: ${detail}. Skipping.`,
    );
    return undefined;
  }

  return first;
}

function findBundled(): string | undefined {
  if (!extensionContext) {
    return undefined;
  }

  const binary = process.platform === "win32" ? "trestle.exe" : "trestle";
  const bundled = path.join(extensionContext.extensionPath, "bin", binary);
  if (!existsSync(bundled)) {
    return undefined;
  }

  if (process.platform !== "win32") {
    try {
      chmodSync(bundled, 0o755);
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      output?.appendLine(
        `Failed to mark bundled binary as executable: ${detail}.`,
      );
    }
  }

  return bundled;
}

async function stopClient(): Promise<void> {
  if (!client) {
    return;
  }

  try {
    await client.stop();
    output?.appendLine("Language server stopped.");
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    output?.appendLine(`Failed to stop language server: ${detail}`);
  }

  client = undefined;
}
