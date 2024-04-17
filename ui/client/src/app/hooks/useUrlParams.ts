import { DisallowCharacters } from "@app/utils/type-utils";
import { objectKeys } from "@app/utils/utils";
import React from "react";
import { useLocation, useNavigate } from "react-router-dom";

// useUrlParams is a generic hook similar to React.useState which stores its state in the URL search params string.
// The state is retained on a page reload, when using the browser back/forward buttons, or when bookmarking the page.
// It can be used to store a value of any type (`TDeserializedParams`) in one or more URL params by providing:
// - A list of `keys` you want to use for the URL params (strings with any characters except colon ":")
// - A `serialize` function to convert this type into an object with string values (`TSerializedParams`)
// - A `deserialize` function to convert the serialized object back to your state's type
// - An optional `keyPrefix` to allow for multiple instances using the same keys on the same page.
// The return value is the same [value, setValue] tuple returned by React.useState.

// Note: You do not need to worry about the keyPrefix in your serialize and deserialize functions.
//       The keys of TDeserializedParams and TSerializedParams have the prefixes omitted.
//       Prefixes are only used at the very first/last step when reading/writing from/to the URLSearchParams object.

export type TSerializedParams<TURLParamKey extends string> = Partial<
  Record<TURLParamKey, string | null>
>;

export interface IUseUrlParamsArgs<
  TDeserializedParams,
  TPersistenceKeyPrefix extends string,
  TURLParamKey extends string,
> {
  isEnabled?: boolean;
  persistenceKeyPrefix?: DisallowCharacters<TPersistenceKeyPrefix, ":">;
  keys: DisallowCharacters<TURLParamKey, ":">[];
  defaultValue: TDeserializedParams;
  serialize: (
    params: Partial<TDeserializedParams>
  ) => TSerializedParams<TURLParamKey>;
  deserialize: (
    serializedParams: TSerializedParams<TURLParamKey>
  ) => TDeserializedParams;
}

export type TURLParamStateTuple<TDeserializedParams> = [
  TDeserializedParams,
  (newParams: Partial<TDeserializedParams>) => void,
];

export const useUrlParams = <
  TDeserializedParams,
  TKeyPrefix extends string,
  TURLParamKey extends string,
>({
  isEnabled = true,
  persistenceKeyPrefix,
  keys,
  defaultValue,
  serialize,
  deserialize,
}: IUseUrlParamsArgs<
  TDeserializedParams,
  TKeyPrefix,
  TURLParamKey
>): TURLParamStateTuple<TDeserializedParams> => {
  type TPrefixedURLParamKey = TURLParamKey | `${TKeyPrefix}:${TURLParamKey}`;

  const navigate = useNavigate();

  const withPrefix = (key: TURLParamKey): TPrefixedURLParamKey =>
    persistenceKeyPrefix ? `${persistenceKeyPrefix}:${key}` : key;

  const withPrefixes = (
    serializedParams: TSerializedParams<TURLParamKey>
  ): TSerializedParams<TPrefixedURLParamKey> =>
    persistenceKeyPrefix
      ? objectKeys(serializedParams).reduce(
          (obj, key) => ({
            ...obj,
            [withPrefix(key)]: serializedParams[key],
          }),
          {} as TSerializedParams<TPrefixedURLParamKey>
        )
      : (serializedParams as TSerializedParams<TPrefixedURLParamKey>);

  const setParams = (newParams: Partial<TDeserializedParams>) => {
    // In case setParams is called multiple times synchronously from the same rendered instance,
    // we use document.location here as the current params so these calls never overwrite each other.
    // This also retains any unrelated params that might be present and allows newParams to be a partial update.
    const { pathname, search } = document.location;
    const existingSearchParams = new URLSearchParams(search);
    // We prefix the params object here so the serialize function doesn't have to care about the keyPrefix.
    const newPrefixedSerializedParams = withPrefixes(serialize(newParams));
    navigate({
      pathname,
      search: trimAndStringifyUrlParams({
        existingSearchParams,
        newPrefixedSerializedParams,
      }),
    });
  };

  // We use useLocation here so we are re-rendering when the params change.
  const urlParams = new URLSearchParams(useLocation().search);
  // We un-prefix the params object here so the deserialize function doesn't have to care about the keyPrefix.

  let allParamsEmpty = true;
  let params: TDeserializedParams = defaultValue;
  if (isEnabled) {
    const serializedParams = keys.reduce(
      (obj, key) => ({
        ...obj,
        [key]: urlParams.get(withPrefix(key)),
      }),
      {} as TSerializedParams<TURLParamKey>
    );
    allParamsEmpty = keys.every((key) => !serializedParams[key]);
    params = allParamsEmpty ? defaultValue : deserialize(serializedParams);
  }

  React.useEffect(() => {
    if (allParamsEmpty) setParams(defaultValue);
    // Leaving this rule enabled results in a cascade of unnecessary useCallbacks:
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [allParamsEmpty]);

  return [params, setParams];
};

export const trimAndStringifyUrlParams = <TPrefixedURLParamKey extends string>({
  existingSearchParams = new URLSearchParams(),
  newPrefixedSerializedParams,
}: {
  existingSearchParams?: URLSearchParams;
  newPrefixedSerializedParams: TSerializedParams<TPrefixedURLParamKey>;
}) => {
  const existingPrefixedSerializedParams =
    Object.fromEntries(existingSearchParams);
  objectKeys(newPrefixedSerializedParams).forEach((key) => {
    // Returning undefined for a property from serialize should result in it being omitted from the partial update.
    if (newPrefixedSerializedParams[key] === undefined) {
      delete newPrefixedSerializedParams[key];
    }
    // Returning null for a property from serialize should result in it being removed from the URL.
    if (newPrefixedSerializedParams[key] === null) {
      delete newPrefixedSerializedParams[key];
      delete existingPrefixedSerializedParams[key];
    }
  });
  const newParams = new URLSearchParams({
    ...existingPrefixedSerializedParams,
    ...newPrefixedSerializedParams,
  });
  newParams.sort();
  return newParams.toString();
};
