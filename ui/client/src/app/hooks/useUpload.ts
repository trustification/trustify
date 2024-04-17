import React from "react";
import axios, {
  AxiosError,
  AxiosPromise,
  AxiosRequestConfig,
  AxiosResponse,
  CancelTokenSource,
} from "axios";
import { FORM_DATA_FILE_KEY } from "@app/Constants";

const CANCEL_MESSAGE = "cancelled";

interface PromiseConfig<T, E> {
  formData: FormData;
  config: AxiosRequestConfig;

  thenFn: (response: AxiosResponse<T>) => void;
  catchFn: (error: AxiosError<E>) => void;
}

interface Upload<T, E> {
  progress: number;
  status: "queued" | "inProgress" | "complete";
  response?: AxiosResponse<T>;
  error?: AxiosError<E>;
  wasCancelled: boolean;
  cancelFn?: CancelTokenSource;
}

const defaultUpload = <T, E>(): Upload<T, E> => ({
  progress: 0,
  status: "queued",
  error: undefined,
  response: undefined,
  wasCancelled: false,
  cancelFn: undefined,
});

interface Status<T, E> {
  uploads: Map<File, Upload<T, E>>;
}

type Action<T, E> =
  | {
      type: "queueUpload";
      payload: {
        file: File;
        cancelFn: CancelTokenSource;
      };
    }
  | {
      type: "updateUploadProgress";
      payload: {
        file: File;
        progress: number;
      };
    }
  | {
      type: "finishUploadSuccessfully";
      payload: {
        file: File;
        response: AxiosResponse<T>;
      };
    }
  | {
      type: "finishUploadWithError";
      payload: {
        file: File;
        error: AxiosError<E>;
      };
    }
  | {
      type: "removeUpload";
      payload: {
        file: File;
      };
    };

const reducer = <T, E>(
  state: Status<T, E>,
  action: Action<T, E>
): Status<T, E> => {
  switch (action.type) {
    case "queueUpload": {
      return {
        ...state,
        uploads: new Map(state.uploads).set(action.payload.file, {
          ...(state.uploads.get(action.payload.file) || defaultUpload()),
          status: "queued",
          cancelFn: action.payload.cancelFn,
        }),
      };
    }
    case "updateUploadProgress": {
      return {
        ...state,
        uploads: new Map(state.uploads).set(action.payload.file, {
          ...(state.uploads.get(action.payload.file) || defaultUpload()),
          progress: action.payload.progress || 0,
          status: "inProgress",
        }),
      };
    }
    case "finishUploadSuccessfully": {
      return {
        ...state,
        uploads: new Map(state.uploads).set(action.payload.file, {
          ...state.uploads.get(action.payload.file)!,
          status: "complete",

          response: action.payload.response,
        }),
      };
    }
    case "finishUploadWithError": {
      return {
        ...state,
        uploads: new Map(state.uploads).set(action.payload.file, {
          ...state.uploads.get(action.payload.file)!,
          status: "complete",
          error: action.payload.error,
          wasCancelled: action.payload.error?.message === CANCEL_MESSAGE,
        }),
      };
    }
    case "removeUpload": {
      const newUploads = new Map(state.uploads);
      newUploads.delete(action.payload.file);
      return {
        ...state,
        uploads: newUploads,
      };
    }
    default:
      throw new Error();
  }
};

const initialState = <T, E>(): Status<T, E> => ({
  uploads: new Map(),
});

export const useUpload = <T, E>({
  parallel,
  uploadFn,
  onSuccess,
  onError,
}: {
  parallel: boolean;
  uploadFn: (
    form: FormData,
    requestConfig: AxiosRequestConfig
  ) => AxiosPromise<T>;
  onSuccess?: (response: AxiosResponse<T>, file: File) => void;
  onError?: (error: AxiosError<E>, file: File) => void;
}) => {
  const [state, dispatch] = React.useReducer(reducer, initialState<T, E>());

  const handleUpload = (acceptedFiles: File[]) => {
    const queue: PromiseConfig<T, E>[] = [];

    for (let index = 0; index < acceptedFiles.length; index++) {
      const file = acceptedFiles[index];

      // Upload
      const formData = new FormData();
      formData.set(FORM_DATA_FILE_KEY, file);

      const cancelFn = axios.CancelToken.source();

      const config: AxiosRequestConfig = {
        headers: {
          "X-Requested-With": "XMLHttpRequest",
        },
        onUploadProgress: (progressEvent: ProgressEvent) => {
          const progress = (progressEvent.loaded / progressEvent.total) * 100;
          dispatch({
            type: "updateUploadProgress",
            payload: { file, progress: Math.round(progress) },
          });
        },
        cancelToken: cancelFn.token,
      };

      dispatch({
        type: "queueUpload",
        payload: {
          file,
          cancelFn,
        },
      });

      const thenFn = (response: AxiosResponse<T>) => {
        dispatch({
          type: "finishUploadSuccessfully",
          payload: { file, response },
        });

        if (onSuccess) onSuccess(response, file);
      };

      const catchFn = (error: AxiosError<E>) => {
        dispatch({
          type: "finishUploadWithError",
          payload: { file, error },
        });

        if (error.message !== CANCEL_MESSAGE) {
          if (onError) onError(error, file);
        }
      };

      const promiseConfig: PromiseConfig<T, E> = {
        formData,
        config,
        thenFn,
        catchFn,
      };

      queue.push(promiseConfig);
    }

    if (parallel) {
      queue.forEach((queue) => {
        uploadFn(queue.formData, queue.config)
          .then(queue.thenFn)
          .catch(queue.catchFn);
      });
    } else {
      queue.reduce(async (prev, next) => {
        await prev;
        return uploadFn(next.formData, next.config)
          .then(next.thenFn)
          .catch(next.catchFn);
      }, Promise.resolve());
    }
  };

  const handleCancelUpload = (file: File) => {
    state.uploads.get(file)?.cancelFn?.cancel(CANCEL_MESSAGE);
  };

  const handleRemoveUpload = (file: File) => {
    dispatch({
      type: "removeUpload",
      payload: { file },
    });
  };

  return {
    uploads: state.uploads as Map<File, Upload<T, E>>,
    handleUpload,
    handleCancelUpload,
    handleRemoveUpload,
  };
};
