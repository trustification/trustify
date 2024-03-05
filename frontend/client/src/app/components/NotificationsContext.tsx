import * as React from "react";
import { AlertProps } from "@patternfly/react-core";

export type INotification = {
  title: string;
  variant: AlertProps["variant"];
  message?: React.ReactNode;
  hideCloseButton?: boolean;
  timeout?: number | boolean;
};

interface INotificationsProvider {
  children: React.ReactNode;
}

interface INotificationsContext {
  pushNotification: (notification: INotification) => void;
  dismissNotification: (key: string) => void;
  notifications: INotification[];
}

const appContextDefaultValue = {} as INotificationsContext;

const notificationDefault: Pick<INotification, "hideCloseButton"> = {
  hideCloseButton: false,
};

export const NotificationsContext = React.createContext<INotificationsContext>(
  appContextDefaultValue
);

export const NotificationsProvider: React.FunctionComponent<
  INotificationsProvider
> = ({ children }: INotificationsProvider) => {
  const [notifications, setNotifications] = React.useState<INotification[]>([]);

  const pushNotification = (
    notification: INotification,
    clearNotificationDelay?: number
  ) => {
    setNotifications([
      ...notifications,
      { ...notificationDefault, ...notification },
    ]);
    setTimeout(() => setNotifications([]), clearNotificationDelay || 10000);
  };

  const dismissNotification = (title: string) => {
    const remainingNotifications = notifications.filter(
      (n) => n.title !== title
    );
    setNotifications(remainingNotifications);
  };

  return (
    <NotificationsContext.Provider
      value={{
        pushNotification,
        dismissNotification,
        notifications,
      }}
    >
      {children}
    </NotificationsContext.Provider>
  );
};
