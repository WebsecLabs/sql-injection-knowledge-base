/**
 * Stand-in for the astro:transitions/client virtual module in unit tests.
 * Tests spy on navigate() with vi.mock to assert client-side navigations.
 */
export async function navigate(_href: string): Promise<void> {}
