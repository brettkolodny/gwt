export const encodeUrlSafe = (string) => {
  return btoa(string).replaceAll("=", "").replaceAll("+", "-").replaceAll("/", "_");
}
