export {};

declare global {
  interface Window {
    /**
     * base64 encoded JS object containing any environment configurations.
     */
    _env: string;
  }
}
