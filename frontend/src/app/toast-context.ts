import { createContext, useContext } from "react";

export const ToastContext = createContext<{
  push: (kind: "success" | "error" | "info", message: string) => void;
}>({ push: () => undefined });

export const useToast = (): {
  push: (kind: "success" | "error" | "info", message: string) => void;
} => useContext(ToastContext);
