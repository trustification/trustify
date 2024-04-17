import * as React from "react";
import { Components } from "react-markdown";
import { CodeBlock, CodeBlockCode, Text } from "@patternfly/react-core";
import spacing from "@patternfly/react-styles/css/utilities/Spacing/spacing";

export const markdownPFComponents: Components = {
  h1: (props) => <Text component="h1" {...props} />,
  h2: (props) => <Text component="h2" {...props} />,
  h3: (props) => <Text component="h3" {...props} />,
  h4: (props) => <Text component="h4" {...props} />,
  h5: (props) => <Text component="h5" {...props} />,
  h6: (props) => <Text component="h6" {...props} />,
  p: (props) => <Text component="p" {...props} />,
  a: (props) => <Text component="a" {...props} />,
  small: (props) => <Text component="small" {...props} />,
  blockquote: (props) => <Text component="blockquote" {...props} />,
  pre: (props) => (
    <CodeBlock className={spacing.mbMd}>
      <CodeBlockCode {...props} />
    </CodeBlock>
  ),
};
