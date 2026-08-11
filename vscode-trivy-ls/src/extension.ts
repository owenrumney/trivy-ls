import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { ExtensionContext, commands, window, workspace } from "vscode";
import {
  DidChangeConfigurationNotification,
  ExecuteCommandRequest,
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
} from "vscode-languageclient/node";

const SECTION = "trivy-ls";

// Commands the server puts on its code actions. VS Code resolves those against
// its global command registry, so each one needs a proxy here that hands the
// request back to the server.
const SERVER_COMMANDS = [
  "trivy-ls.scan",
  "trivy-ls.openUrl",
  "trivy-ls.addToIgnoreFile",
];

let client: LanguageClient | undefined;

export async function activate(context: ExtensionContext): Promise<void> {
  const serverPath = resolveServerPath(context);
  if (!serverPath) {
    return;
  }

  const serverOptions: ServerOptions = {
    run: { command: serverPath },
    debug: { command: serverPath },
  };

  const clientOptions: LanguageClientOptions = {
    // Trivy reports secrets in files of any type, so the client has to be
    // willing to send hover and code action requests for all of them.
    documentSelector: [{ scheme: "file" }],
    initializationOptions: serverConfig(),
  };

  client = new LanguageClient(
    SECTION,
    "Trivy Language Server",
    serverOptions,
    clientOptions,
  );

  for (const command of SERVER_COMMANDS) {
    context.subscriptions.push(
      commands.registerCommand(command, (...args: unknown[]) =>
        executeOnServer(command, args),
      ),
    );
  }

  context.subscriptions.push(
    commands.registerCommand("trivy-ls.restart", () => client?.restart()),
    workspace.onDidChangeConfiguration(onConfigurationChanged),
  );

  await client.start();
}

export function deactivate(): Thenable<void> | undefined {
  return client?.stop();
}

async function executeOnServer(
  command: string,
  args: unknown[],
): Promise<void> {
  if (!client) {
    return;
  }
  try {
    await client.sendRequest(ExecuteCommandRequest.type, {
      command,
      arguments: args,
    });
  } catch (err) {
    window.showErrorMessage(`Trivy: ${command} failed: ${errorMessage(err)}`);
  }
}

async function onConfigurationChanged(event: {
  affectsConfiguration: (section: string) => boolean;
}): Promise<void> {
  if (!event.affectsConfiguration(SECTION)) {
    return;
  }

  // serverPath is read once when the process is spawned, so it is the only
  // setting a running server cannot pick up.
  if (event.affectsConfiguration(`${SECTION}.serverPath`)) {
    const choice = await window.showInformationMessage(
      "Trivy: the server path changed. Restart the language server to use it?",
      "Restart",
    );
    if (choice === "Restart") {
      await client?.restart();
    }
    return;
  }

  await client?.sendNotification(DidChangeConfigurationNotification.type, {
    settings: serverConfig(),
  });
}

// serverConfig maps the extension's settings onto the server's configuration.
// serverPath is deliberately absent: it is about launching the process, not
// about how it scans.
function serverConfig(): Record<string, unknown> {
  const config = workspace.getConfiguration(SECTION);
  return {
    trivyPath: config.get<string>("trivyPath", ""),
    scanners: config.get<string[]>("scanners", []),
    severities: config.get<string[]>("severities", []),
    ignoreFile: config.get<string>("ignoreFile", ""),
    configFile: config.get<string>("configFile", ""),
    extraArgs: config.get<string[]>("extraArgs", []),
    scanOnSave: config.get<boolean>("scanOnSave", true),
    scanOnOpen: config.get<boolean>("scanOnOpen", true),
    fullRange: config.get<boolean>("fullRange", false),
  };
}

// resolveServerPath finds the server binary, reporting the failure rather than
// letting the client fail silently into its output channel.
function resolveServerPath(context: ExtensionContext): string | undefined {
  const custom = workspace.getConfiguration(SECTION).get<string>("serverPath");
  if (custom) {
    if (!fs.existsSync(custom)) {
      window.showErrorMessage(
        `Trivy: no server binary at ${custom}. Check the trivy-ls.serverPath setting.`,
      );
      return undefined;
    }
    return custom;
  }

  const binary = os.platform() === "win32" ? "trivy-ls.exe" : "trivy-ls";
  const bundled = path.join(context.extensionPath, "bin", binary);
  if (fs.existsSync(bundled)) {
    return bundled;
  }

  // Each published .vsix targets one platform. A universal build, or a
  // platform with no published build, lands here.
  window.showErrorMessage(
    "Trivy: this build of the extension has no bundled server for your platform. " +
      "Install trivy-ls and set the trivy-ls.serverPath setting.",
  );
  return undefined;
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
