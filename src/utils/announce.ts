/**
 * Screen reader announcements through a shared polite live region.
 * @module announce
 */

const REGION_ID = "sr-announcer";

/**
 * Announce a short status message to screen readers without moving focus.
 * The region is created on first use and re-created if a View Transition
 * swapped the body without it.
 */
export function announce(message: string): void {
  let region = document.getElementById(REGION_ID);
  if (!region) {
    region = document.createElement("div");
    region.id = REGION_ID;
    region.className = "sr-only";
    region.setAttribute("role", "status");
    document.body.append(region);
  }

  // Clear first so repeating the same message is announced again
  region.textContent = "";
  requestAnimationFrame(() => {
    region.textContent = message;
  });
}
