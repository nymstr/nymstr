import { useEffect, useState } from "react";
import { Button } from "@/components/shadcn/button";
import { Input } from "@/components/shadcn/input";
import { Avatar, AvatarFallback } from "@/components/shadcn/avatar";
import { X, Users, Loader2, RefreshCw, Plus } from "lucide-react";
import * as api from "@/services/api";
import type { Group } from "@/types";
import { useGroupStore } from "@/stores/groupStore";
import { useGroupJoin } from "@/hooks/useGroupJoin";
import { showToast } from "@/hooks/useToast";

interface GroupJoinModalProps {
  onClose: () => void;
  onJoined: (groupAddress: string) => void;
}

export function GroupJoinModal({ onClose, onJoined }: GroupJoinModalProps) {
  const [address, setAddress] = useState("");
  const [loading, setLoading] = useState(false);
  const discoveredGroups = useGroupStore((s) => s.discoveredGroups);
  const setDiscoveredGroups = useGroupStore((s) => s.setDiscoveredGroups);
  const isDiscovering = useGroupStore((s) => s.isDiscovering);
  const setDiscovering = useGroupStore((s) => s.setDiscovering);
  const { joinGroup, isJoining, isJoined, isPendingApproval } = useGroupJoin();

  const discover = async () => {
    setDiscovering(true);
    try {
      const groups = await api.discoverGroups();
      setDiscoveredGroups(groups);
    } catch (err) {
      showToast.error(
        "Discovery failed",
        err instanceof Error ? err.message : "Unknown error",
      );
    } finally {
      setDiscovering(false);
    }
  };

  useEffect(() => {
    discover();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleJoinByAddress = async (e: React.FormEvent) => {
    e.preventDefault();
    const addr = address.trim();
    if (!addr) return;
    setLoading(true);
    try {
      await joinGroup(addr);
      onJoined(addr);
      onClose();
    } catch (err) {
      showToast.error(
        "Join failed",
        err instanceof Error ? err.message : "Unknown error",
      );
    } finally {
      setLoading(false);
    }
  };

  const handleJoinDiscovered = async (g: Group) => {
    try {
      await joinGroup(g.address, g.name);
      onJoined(g.address);
      onClose();
    } catch (err) {
      showToast.error(
        "Join failed",
        err instanceof Error ? err.message : "Unknown error",
      );
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        className="w-full max-w-md rounded-xl border border-border bg-card shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-border px-4 py-3">
          <h2 className="text-lg font-semibold text-foreground">Join a group</h2>
          <Button
            variant="ghost"
            size="icon"
            onClick={onClose}
            className="text-muted-foreground hover:text-foreground"
          >
            <X className="h-5 w-5" />
          </Button>
        </div>

        <form onSubmit={handleJoinByAddress} className="space-y-2 p-4">
          <label className="text-sm font-medium text-foreground">
            By group address
          </label>
          <div className="flex gap-2">
            <Input
              value={address}
              onChange={(e) => setAddress(e.target.value)}
              placeholder="Group Nym address..."
              className="font-mono text-xs"
              disabled={loading}
            />
            <Button type="submit" disabled={!address.trim() || loading}>
              {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />}
            </Button>
          </div>
        </form>

        <div className="flex items-center justify-between border-t border-border px-4 py-2">
          <span className="text-sm font-medium text-foreground">Discoverable</span>
          <Button
            variant="ghost"
            size="icon-sm"
            onClick={discover}
            disabled={isDiscovering}
            className="text-muted-foreground hover:text-foreground"
          >
            <RefreshCw className={isDiscovering ? "h-4 w-4 animate-spin" : "h-4 w-4"} />
          </Button>
        </div>

        <div className="max-h-80 overflow-y-auto">
          {isDiscovering && discoveredGroups.length === 0 ? (
            <div className="flex items-center justify-center gap-2 py-8 text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" />
              <span className="text-sm">Discovering groups...</span>
            </div>
          ) : discoveredGroups.length === 0 ? (
            <div className="px-4 py-8 text-center text-sm text-muted-foreground">
              No public groups discovered yet.
            </div>
          ) : (
            <div className="flex flex-col divide-y divide-border">
              {discoveredGroups.map((g) => {
                const joining = isJoining(g.address);
                const joined = isJoined(g.address);
                const pending = isPendingApproval(g.address);
                return (
                  <div
                    key={g.address}
                    className="flex items-center gap-3 px-4 py-3"
                  >
                    <Avatar className="h-10 w-10">
                      <AvatarFallback>
                        <Users className="h-5 w-5" />
                      </AvatarFallback>
                    </Avatar>
                    <div className="flex-1 overflow-hidden">
                      <p className="truncate font-medium text-foreground">
                        {g.name}
                      </p>
                      <p className="truncate text-xs text-muted-foreground">
                        {g.memberCount} members
                      </p>
                    </div>
                    <Button
                      size="sm"
                      onClick={() => handleJoinDiscovered(g)}
                      disabled={joining || joined || pending}
                      variant={joined ? "secondary" : "default"}
                    >
                      {joined
                        ? "Joined"
                        : pending
                          ? "Pending"
                          : joining
                            ? "..."
                            : "Join"}
                    </Button>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
