import React from "react";

type ModalState<T> =
  | { mode: "create"; resource: null }
  | { mode: "create"; resource: T }
  | { mode: "edit"; resource: T }
  | null;

export default function useCreateEditModalState<T>() {
  const [modalState, setModalState] = React.useState<ModalState<T>>(null);
  const isModalOpen = modalState !== null;

  return {
    modalState,
    setModalState,
    isModalOpen,
  };
}
