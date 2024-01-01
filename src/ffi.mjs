export const base64Encode = (string) => {
  return btoa(string);
}

export const base64Decode = (string) => {
  return atob(string);
}
