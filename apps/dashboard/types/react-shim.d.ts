/**
 * Minimal ambient declarations for React 19 and react-dom/client.
 *
 * Why this file exists: `@types/react` is an npm package and the registry is blocked by
 * egress policy in the build environment (docs/DECISIONS.md D-004). Without any
 * declarations `tsc --noEmit` cannot run at all, which would mean no typechecking of the
 * dashboard whatsoever.
 *
 * What it does and does not buy: our own code is fully typechecked -- component props,
 * the `types.ts` interfaces mirroring the API, hook return values, and every call site
 * in `src/`. React's own surface is typed loosely (hooks are generic, `ReactNode` is
 * permissive), so a misuse of a React internal would not be caught. That is a smaller
 * gap than having no typechecker, and it is recorded in `docs/VERIFICATION.md` rather
 * than being presented as full React typing.
 *
 * On a machine with registry access, delete this file and
 * `npm i -D @types/react @types/react-dom` for complete types.
 */

declare namespace JSX {
  interface Element {
    type: unknown;
    props: unknown;
    key: string | number | null;
  }
  interface ElementClass {
    render(): unknown;
  }
  interface ElementAttributesProperty {
    props: Record<string, unknown>;
  }
  interface ElementChildrenAttribute {
    children: Record<string, unknown>;
  }
  interface IntrinsicAttributes {
    key?: string | number | null | undefined;
  }
  interface IntrinsicClassAttributes<T> {
    ref?: unknown;
  }
  // Intrinsic elements are intentionally permissive: without @types/react there is no
  // authoritative DOM-prop table, and inventing a partial one would produce false errors.
  interface IntrinsicElements {
    [tag: string]: Record<string, unknown>;
  }
}

declare module "react" {
  export type ReactNode =
    | JSX.Element
    | string
    | number
    | boolean
    | null
    | undefined
    | Iterable<ReactNode>;

  export type Key = string | number;

  export interface FC<P = Record<string, never>> {
    (props: P & { children?: ReactNode }): JSX.Element | null;
    displayName?: string;
  }
  export type FunctionComponent<P = Record<string, never>> = FC<P>;

  export interface MutableRefObject<T> {
    current: T;
  }

  export type Dispatch<A> = (value: A) => void;
  export type SetStateAction<S> = S | ((prev: S) => S);

  export function useState<S>(initial: S | (() => S)): [S, Dispatch<SetStateAction<S>>];
  export function useState<S = undefined>(): [S | undefined, Dispatch<SetStateAction<S | undefined>>];
  export function useEffect(effect: () => void | (() => void), deps?: readonly unknown[]): void;
  export function useLayoutEffect(effect: () => void | (() => void), deps?: readonly unknown[]): void;
  export function useMemo<T>(factory: () => T, deps: readonly unknown[]): T;
  export function useCallback<T extends (...args: never[]) => unknown>(fn: T, deps: readonly unknown[]): T;
  export function useRef<T>(initial: T): MutableRefObject<T>;
  export function useRef<T = undefined>(): MutableRefObject<T | undefined>;
  export function useId(): string;
  export function useReducer<S, A>(
    reducer: (state: S, action: A) => S,
    initial: S,
  ): [S, Dispatch<A>];

  export const StrictMode: FC<{ children?: ReactNode }>;
  export const Fragment: FC<{ children?: ReactNode }>;

  export function createElement(type: unknown, props?: unknown, ...children: unknown[]): JSX.Element;

  export interface ChangeEvent<T = Element> {
    target: T & { value: string; checked: boolean };
    currentTarget: T & { value: string };
    preventDefault(): void;
    stopPropagation(): void;
  }
  export interface MouseEvent<T = Element> {
    target: T;
    currentTarget: T;
    preventDefault(): void;
    stopPropagation(): void;
  }
  export interface FormEvent<T = Element> {
    target: T;
    currentTarget: T;
    preventDefault(): void;
  }
}

declare module "react/jsx-runtime" {
  export function jsx(type: unknown, props: unknown, key?: unknown): JSX.Element;
  export function jsxs(type: unknown, props: unknown, key?: unknown): JSX.Element;
  export const Fragment: unknown;
}

declare module "react/jsx-dev-runtime" {
  export function jsxDEV(type: unknown, props: unknown, key?: unknown): JSX.Element;
  export const Fragment: unknown;
}

declare module "react-dom/client" {
  import type { ReactNode } from "react";
  export interface Root {
    render(children: ReactNode): void;
    unmount(): void;
  }
  export function createRoot(container: Element | DocumentFragment): Root;
  export function hydrateRoot(container: Element, children: ReactNode): Root;
}
