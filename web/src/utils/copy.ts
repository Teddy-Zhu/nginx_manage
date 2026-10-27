export async function copyText(text: string) {
  if (window.isSecureContext && navigator.clipboard) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const previous =
    document.activeElement instanceof HTMLElement
      ? document.activeElement
      : null;
  const input = document.createElement("textarea");
  input.value = text;
  input.setAttribute("readonly", "");
  input.style.cssText = "position:fixed;left:-9999px;top:0";
  document.body.appendChild(input);
  try {
    input.select();
    if (!document.execCommand("copy")) throw new Error("无法访问剪贴板");
  } finally {
    input.remove();
    previous?.focus();
  }
}
