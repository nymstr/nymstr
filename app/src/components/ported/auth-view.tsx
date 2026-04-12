import { useEffect, useState } from "react";
import {
  MessageCircle,
  Plus,
  ArrowLeft,
  Eye,
  EyeOff,
  Server,
} from "lucide-react";
import { Button } from "@/components/shadcn/button";
import { Input } from "@/components/shadcn/input";
import { FieldGroup, Field, FieldLabel } from "@/components/shadcn/field";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn/select";
import { Avatar, AvatarFallback } from "@/components/shadcn/avatar";
import { HamsterLoader } from "./hamster-loader";
import * as api from "@/services/api";
import { useAuthStore } from "@/stores/authStore";
import { useConnectionStore } from "@/stores/connectionStore";

function describeError(err: unknown): string {
  if (err instanceof Error) return err.message;
  if (typeof err === "string") return err;
  if (err && typeof err === "object") {
    const maybe = err as { message?: unknown; code?: unknown };
    if (typeof maybe.message === "string" && maybe.message) return maybe.message;
    if (typeof maybe.code === "string" && maybe.code) return maybe.code;
    try {
      return JSON.stringify(err);
    } catch {
      return String(err);
    }
  }
  return String(err);
}

type Mode = "login" | "create";

function initials(name: string) {
  return name
    .split(" ")
    .filter(Boolean)
    .slice(0, 2)
    .map((n) => n[0]!.toUpperCase())
    .join("");
}

export function AuthView() {
  const setAuthenticated = useAuthStore((s) => s.setAuthenticated);
  const { setServerAddress: setStoreServerAddress } = useConnectionStore();

  const [mode, setMode] = useState<Mode>("login");
  const [savedUsername, setSavedUsername] = useState<string | null>(null);
  const [selectedUsername, setSelectedUsername] = useState<string>("");

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);

  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [loadingMessage, setLoadingMessage] = useState("");

  const [showServer, setShowServer] = useState(false);
  const [serverAddress, setServerAddressInput] = useState("");
  const [serverSaved, setServerSaved] = useState(false);

  useEffect(() => {
    (async () => {
      try {
        const init = await api.initialize();
        if (init.hasUser && init.username) {
          setSavedUsername(init.username);
          setSelectedUsername(init.username);
          setMode("login");
        } else {
          setMode("create");
        }
      } catch (err) {
        console.error("[Auth] initialize failed:", err);
        setMode("create");
      }
      try {
        const addr = await api.getServerAddress();
        if (addr) {
          setServerAddressInput(addr);
          setStoreServerAddress(addr);
        }
      } catch (err) {
        console.error("[Auth] getServerAddress failed:", err);
      }
    })();
  }, [setStoreServerAddress]);

  const handleSaveServerAddress = async () => {
    const addr = serverAddress.trim();
    if (!addr) {
      setError("Server address is required");
      return;
    }
    try {
      await api.setServerAddress(addr);
      setStoreServerAddress(addr);
      setServerSaved(true);
      setTimeout(() => setServerSaved(false), 2000);
    } catch (err) {
      setError(describeError(err) || "Failed to save server address");
    }
  };

  const handleLogin = async () => {
    setError("");
    if (!selectedUsername) {
      setError("Please select an account");
      return;
    }
    if (!password) {
      setError("Please enter your password");
      return;
    }

    setIsLoading(true);
    try {
      setLoadingMessage("Connecting to mixnet...");
      await api.connectToMixnetForUser(selectedUsername);
      setLoadingMessage("Signing in...");
      const user = await api.pingServer(selectedUsername, password);
      setLoadingMessage("Loading conversations...");
      setAuthenticated(user);
    } catch (err) {
      setError(describeError(err) || "Sign in failed");
      setIsLoading(false);
      setLoadingMessage("");
    }
  };

  const handleCreateAccount = async () => {
    setError("");
    if (!username.trim()) return setError("Please enter a username");
    if (username.length < 3)
      return setError("Username must be at least 3 characters");
    if (!/^[a-zA-Z0-9_]+$/.test(username))
      return setError("Username can only contain letters, numbers, and underscores");
    if (!password) return setError("Please enter a password");
    if (password.length < 6)
      return setError("Password must be at least 6 characters");
    if (password !== confirmPassword) return setError("Passwords do not match");

    setIsLoading(true);
    try {
      setLoadingMessage("Connecting to mixnet...");
      await api.connectToMixnet();
      setLoadingMessage("Generating keypair...");
      // Backend generates keys inside register_user
      setLoadingMessage("Registering with server...");
      const user = await api.registerUser(username.toLowerCase(), password);
      setLoadingMessage("Initializing secure messaging...");
      setAuthenticated(user);
    } catch (err) {
      setError(describeError(err) || "Account creation failed");
      setIsLoading(false);
      setLoadingMessage("");
    }
  };

  if (isLoading) {
    return (
      <div className="flex h-dvh items-center justify-center bg-background p-4">
        <HamsterLoader message={loadingMessage} />
      </div>
    );
  }

  return (
    <div className="h-dvh overflow-y-auto bg-background">
      <div className="mx-auto flex min-h-full w-full max-w-sm flex-col justify-center p-4">
        <div className="mb-8 text-center">
          <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-2xl bg-primary">
            <MessageCircle className="h-8 w-8 text-primary-foreground" />
          </div>
          <h1 className="text-2xl font-semibold text-foreground">Nymstr</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            {mode === "login" ? "Welcome back" : "Create your account"}
          </p>
        </div>

        <div className="rounded-xl border border-border bg-card p-6">
          {mode === "login" ? (
            <div className="space-y-4">
              <FieldGroup>
                <Field>
                  <FieldLabel>Account</FieldLabel>
                  {savedUsername ? (
                    <Select
                      value={selectedUsername}
                      onValueChange={setSelectedUsername}
                    >
                      <SelectTrigger className="w-full">
                        <SelectValue placeholder="Select an account">
                          {selectedUsername && (
                            <div className="flex items-center gap-2">
                              <Avatar className="h-5 w-5">
                                <AvatarFallback>
                                  {initials(selectedUsername)}
                                </AvatarFallback>
                              </Avatar>
                              <span>@{selectedUsername}</span>
                            </div>
                          )}
                        </SelectValue>
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value={savedUsername}>
                          <div className="flex items-center gap-2">
                            <Avatar className="h-5 w-5">
                              <AvatarFallback>
                                {initials(savedUsername)}
                              </AvatarFallback>
                            </Avatar>
                            <span>@{savedUsername}</span>
                          </div>
                        </SelectItem>
                      </SelectContent>
                    </Select>
                  ) : (
                    <div className="relative">
                      <span className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground">
                        @
                      </span>
                      <Input
                        value={selectedUsername}
                        onChange={(e) =>
                          setSelectedUsername(e.target.value.toLowerCase())
                        }
                        placeholder="username"
                        className="pl-7"
                      />
                    </div>
                  )}
                </Field>

                <Field>
                  <FieldLabel>Password</FieldLabel>
                  <div className="relative">
                    <Input
                      type={showPassword ? "text" : "password"}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      onKeyDown={(e) => e.key === "Enter" && handleLogin()}
                      placeholder="Enter your password"
                      className="pr-10"
                      autoComplete="current-password"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                    >
                      {showPassword ? (
                        <EyeOff className="h-4 w-4" />
                      ) : (
                        <Eye className="h-4 w-4" />
                      )}
                    </button>
                  </div>
                </Field>
              </FieldGroup>

              {error && <p className="text-sm text-destructive">{error}</p>}

              <Button onClick={handleLogin} className="w-full">
                Sign In
              </Button>

              <div className="relative">
                <div className="absolute inset-0 flex items-center">
                  <div className="w-full border-t border-border" />
                </div>
                <div className="relative flex justify-center text-xs">
                  <span className="bg-card px-2 text-muted-foreground">or</span>
                </div>
              </div>

              <Button
                variant="outline"
                onClick={() => {
                  setMode("create");
                  setError("");
                  setPassword("");
                }}
                className="w-full gap-2"
              >
                <Plus className="h-4 w-4" />
                Create New Account
              </Button>
            </div>
          ) : (
            <div className="space-y-4">
              {savedUsername && (
                <button
                  type="button"
                  onClick={() => {
                    setMode("login");
                    setError("");
                    setUsername("");
                    setPassword("");
                    setConfirmPassword("");
                  }}
                  className="flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
                >
                  <ArrowLeft className="h-4 w-4" />
                  Back to login
                </button>
              )}

              <FieldGroup>
                <Field>
                  <FieldLabel>Username</FieldLabel>
                  <div className="relative">
                    <span className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground">
                      @
                    </span>
                    <Input
                      type="text"
                      value={username}
                      onChange={(e) => setUsername(e.target.value.toLowerCase())}
                      placeholder="username"
                      className="pl-7"
                    />
                  </div>
                </Field>

                <Field>
                  <FieldLabel>Password</FieldLabel>
                  <div className="relative">
                    <Input
                      type={showPassword ? "text" : "password"}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="Create a password"
                      className="pr-10"
                      autoComplete="new-password"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                    >
                      {showPassword ? (
                        <EyeOff className="h-4 w-4" />
                      ) : (
                        <Eye className="h-4 w-4" />
                      )}
                    </button>
                  </div>
                  <p className="mt-1 text-xs text-muted-foreground">
                    Used to encrypt your private key locally
                  </p>
                </Field>

                <Field>
                  <FieldLabel>Confirm Password</FieldLabel>
                  <Input
                    type={showPassword ? "text" : "password"}
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && handleCreateAccount()}
                    placeholder="Confirm your password"
                    autoComplete="new-password"
                  />
                </Field>
              </FieldGroup>

              {error && <p className="text-sm text-destructive">{error}</p>}

              <Button onClick={handleCreateAccount} className="w-full">
                Create Account
              </Button>
            </div>
          )}
        </div>

        <div className="mt-4 flex items-center justify-center gap-2 text-xs text-muted-foreground">
          <span>Your keys are stored locally and encrypted with your password</span>
        </div>

        <div className="mt-3 flex justify-center">
          <button
            type="button"
            onClick={() => setShowServer(!showServer)}
            className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
          >
            <Server className="h-3 w-3" />
            {showServer ? "Hide server settings" : "Server settings"}
          </button>
        </div>

        {showServer && (
          <div className="mt-3 rounded-xl border border-border bg-card p-4">
            <FieldLabel className="mb-2 text-xs">
              Nymstr discovery server address
            </FieldLabel>
            <Input
              type="text"
              placeholder="Nym address..."
              value={serverAddress}
              onChange={(e) => setServerAddressInput(e.target.value)}
              className="font-mono text-xs"
            />
            <Button
              type="button"
              onClick={handleSaveServerAddress}
              size="sm"
              variant={serverSaved ? "secondary" : "default"}
              className="mt-2 w-full"
            >
              {serverSaved ? "Saved!" : "Save"}
            </Button>
          </div>
        )}
      </div>
    </div>
  );
}
