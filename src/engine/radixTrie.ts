interface TrieNode<T> {
  left: TrieNode<T> | null;
  right: TrieNode<T> | null;
  value: T | null;
}

export class BinaryRadixTrie<T> {
  private root: TrieNode<T> = {
    left: null,
    right: null,
    value: null,
  };

  insert(networkUint32: number, prefixLen: number, value: T): void {
    let node = this.root;
    for (let i = 0; i < prefixLen; i++) {
      const bit = (networkUint32 >>> (31 - i)) & 1;
      if (bit === 0) {
        if (!node.left) {
          node.left = { left: null, right: null, value: null };
        }
        node = node.left;
      } else {
        if (!node.right) {
          node.right = { left: null, right: null, value: null };
        }
        node = node.right;
      }
    }
    node.value = value;
  }

  longestPrefixMatch(ipUint32: number): T | null {
    let node: TrieNode<T> | null = this.root;
    let best: T | null = this.root.value;

    for (let i = 0; i < 32 && node; i++) {
      const bit = (ipUint32 >>> (31 - i)) & 1;
      node = bit === 0 ? node.left : node.right;
      if (node && node.value !== null) {
        best = node.value;
      }
    }
    return best;
  }
}

export class BinaryRadixTrie6<T> {
  private root: TrieNode<T> = {
    left: null,
    right: null,
    value: null,
  };

  insert(networkBigInt: bigint, prefixLen: number, value: T): void {
    let node = this.root;
    for (let i = 0; i < prefixLen; i++) {
      const bit = (networkBigInt >> BigInt(127 - i)) & 1n;
      if (bit === 0n) {
        if (!node.left) {
          node.left = { left: null, right: null, value: null };
        }
        node = node.left;
      } else {
        if (!node.right) {
          node.right = { left: null, right: null, value: null };
        }
        node = node.right;
      }
    }
    node.value = value;
  }

  longestPrefixMatch(ipBigInt: bigint): T | null {
    let node: TrieNode<T> | null = this.root;
    let best: T | null = this.root.value;

    for (let i = 0; i < 128 && node; i++) {
      const bit = (ipBigInt >> BigInt(127 - i)) & 1n;
      node = bit === 0n ? node.left : node.right;
      if (node && node.value !== null) {
        best = node.value;
      }
    }
    return best;
  }
}

