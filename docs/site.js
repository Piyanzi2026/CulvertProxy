(() => {
  const copyButtons = document.querySelectorAll("[data-copy-target]");

  async function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return;
    }

    const helper = document.createElement("textarea");
    helper.value = text;
    helper.setAttribute("readonly", "");
    helper.style.position = "fixed";
    helper.style.opacity = "0";
    document.body.appendChild(helper);
    helper.select();
    const copied = document.execCommand("copy");
    helper.remove();
    if (!copied) {
      throw new Error("copy failed");
    }
  }

  copyButtons.forEach((button) => {
    button.setAttribute("aria-live", "polite");
    const label = button.textContent;

    button.addEventListener("click", async () => {
      const target = document.getElementById(button.dataset.copyTarget);
      if (!target) {
        return;
      }

      try {
        await copyText(target.textContent.trim());
        button.textContent = "已复制";
      } catch {
        button.textContent = "复制失败，请手动选择";
      }

      window.setTimeout(() => {
        button.textContent = label;
      }, 1800);
    });
  });
})();
