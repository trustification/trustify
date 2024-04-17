import { useLocalStorage } from "@app/hooks/useStorage";

export interface ColumnState<TColumnKey extends string> {
  id: TColumnKey;
  label: string;
  isVisible: boolean;
}

export interface IColumnState<TColumnKey extends string> {
  columns: ColumnState<TColumnKey>[];
  setColumns: (newColumns: ColumnState<TColumnKey>[]) => void;
}

interface IColumnStateArgs<TColumnKey extends string> {
  initialColumns: ColumnState<TColumnKey>[];
  columnsKey: string;
}

export const useColumnState = <TColumnKey extends string>(
  args: IColumnStateArgs<TColumnKey>
): IColumnState<TColumnKey> => {
  const [columns, setColumns] = useLocalStorage<ColumnState<TColumnKey>[]>({
    key: args.columnsKey,
    defaultValue: args.initialColumns,
  });

  return { columns, setColumns };
};
