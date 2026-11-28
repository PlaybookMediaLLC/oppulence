"use client";

import { Button } from "@oppulence/ui/components/button";
import { Textarea } from "@oppulence/ui/components/textarea";
import { cn } from "@/lib/utils";
import { sanitizeDisplayText } from "@/lib/sanitize-display";
import { MessageCircleIcon, ArrowUpIcon } from "@/lib/icons";
import type { ComponentProps } from "react";
import { useState, useRef, useEffect } from "react";

export type AskHumanRequestProps = ComponentProps<"div"> & {
  query: string;
  options?: string[];
  onResponse: (response: string) => void;
  isProcessing?: boolean;
};

export const AskHumanRequest = ({
  className,
  query,
  options,
  onResponse,
  isProcessing = false,
  ...props
}: AskHumanRequestProps) => {
  const [response, setResponse] = useState("");
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const hasOptions = Array.isArray(options) && options.length > 0;
  const sanitizedQuery = sanitizeDisplayText(query);
  const sanitizedOptions = Array.isArray(options)
    ? options.map((opt) => ({ raw: opt, safe: sanitizeDisplayText(opt) }))
    : [];
  const hasHiddenChars =
    sanitizedQuery.hasHiddenChars || sanitizedOptions.some((o) => o.safe.hasHiddenChars);

  useEffect(() => {
    // Auto-focus the textarea when in free-text mode; nothing to focus for buttons.
    if (!hasOptions) {
      textareaRef.current?.focus();
    }
  }, [hasOptions]);

  const handleSubmit = () => {
    const trimmed = response.trim();
    if (trimmed && !isProcessing) {
      onResponse(trimmed);
      setResponse("");
    }
  };

  const handleOptionClick = (option: string) => {
    if (isProcessing) return;
    onResponse(option);
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSubmit();
    }
  };

  const canSubmit = Boolean(response.trim()) && !isProcessing;

  return (
    <div
      className={cn(
        "not-prose mb-4 w-full rounded-none border border-blue-500/50 bg-blue-50/50 dark:bg-blue-950/20",
        className,
      )}
      {...props}
    >
      <div className="p-4 space-y-4">
        <div className="flex items-start gap-3">
          <MessageCircleIcon className="size-5 text-blue-600 dark:text-blue-500 shrink-0 mt-0.5" />
          <div className="flex-1 space-y-3">
            <div>
              <h3 className="font-semibold text-sm text-foreground mb-1">
                Question from Agent
              </h3>
              <p className="text-sm text-foreground whitespace-pre-wrap">
                {sanitizedQuery.text}
              </p>
              {hasHiddenChars && (
                <p className="mt-1.5 text-xs text-destructive">
                  Warning: Contains hidden or bidirectional Unicode characters (escaped as [U+XXXX]).
                </p>
              )}
            </div>
            {hasOptions ? (
              <div className="flex flex-wrap gap-2">
                {sanitizedOptions.map(({ raw, safe }) => (
                  <Button
                    key={raw}
                    variant="outline"
                    size="sm"
                    onClick={() => handleOptionClick(raw)}
                    disabled={isProcessing}
                    className="bg-background"
                  >
                    {safe.text}
                  </Button>
                ))}
              </div>
            ) : (
              <div className="space-y-2">
                <Textarea
                  ref={textareaRef}
                  value={response}
                  onChange={(e) => setResponse(e.target.value)}
                  onKeyDown={handleKeyDown}
                  placeholder="Type your response..."
                  disabled={isProcessing}
                  rows={3}
                  className="resize-none"
                />
                <div className="flex justify-end">
                  <Button
                    variant="default"
                    size="sm"
                    onClick={handleSubmit}
                    disabled={!canSubmit}
                    className="gap-2"
                  >
                    <ArrowUpIcon className="size-4" />
                    Send Response
                  </Button>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
