import type { Node as JsonNode } from 'jsonc-parser';

export type { JsonNode };

export function prop(node: JsonNode | undefined, key: string): JsonNode | undefined {
  if (!node || node.type !== 'object' || !node.children) return undefined;
  for (const p of node.children) {
    if (p.children?.[0]?.value === key) return p.children[1];
  }
  return undefined;
}

export function propKey(node: JsonNode | undefined, key: string): JsonNode | undefined {
  if (!node || node.type !== 'object' || !node.children) return undefined;
  for (const p of node.children) {
    if (p.children?.[0]?.value === key) return p.children[0];
  }
  return undefined;
}

export function entries(node: JsonNode | undefined): { key: string; keyNode: JsonNode; value: JsonNode }[] {
  if (!node || node.type !== 'object' || !node.children) return [];
  const out: { key: string; keyNode: JsonNode; value: JsonNode }[] = [];
  for (const p of node.children) {
    const k = p.children?.[0];
    const v = p.children?.[1];
    if (k && v && typeof k.value === 'string') out.push({ key: k.value, keyNode: k, value: v });
  }
  return out;
}

export function str(node: JsonNode | undefined): string | undefined {
  return node?.type === 'string' ? (node.value as string) : undefined;
}

export function range(node: JsonNode): [number, number] {
  return [node.offset, node.offset + node.length];
}

/** Depth-first search for object properties with one of the given names. */
export function findProps(root: JsonNode | undefined, names: Set<string>, maxDepth = 6): { key: string; keyNode: JsonNode; value: JsonNode }[] {
  const out: { key: string; keyNode: JsonNode; value: JsonNode }[] = [];
  const walk = (n: JsonNode, depth: number) => {
    if (depth > maxDepth) return;
    if (n.type === 'object') {
      for (const e of entries(n)) {
        if (names.has(e.key)) out.push(e);
        else walk(e.value, depth + 1);
      }
    } else if (n.type === 'array' && n.children) {
      for (const c of n.children) walk(c, depth + 1);
    }
  };
  if (root) walk(root, 0);
  return out;
}
