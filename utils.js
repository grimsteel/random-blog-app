import { dirname } from "path";
import { fileURLToPath } from "url";

/**
 * @returns the directory of the current file
 */
export function dir() {
  return dirname(fileURLToPath(import.meta.url));
}