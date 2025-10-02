import { Classic } from "@caido/primevue";
import PrimeVue from "primevue/config";
import { createApp } from "vue";

import { SDKPlugin } from "./plugins/sdk";
import "./styles/index.css";
import type { FrontendSDK } from "./types";
import App from "./views/App.vue";

export const init = (sdk: FrontendSDK) => {
  const app = createApp(App);

  app.use(PrimeVue, {
    unstyled: true,
    pt: Classic,
  });

  app.use(SDKPlugin, sdk);

  const root = document.createElement("div");
  root.style.height = "100%";
  root.style.width = "100%";
  root.id = "plugin--frontend";

  app.mount(root);

  sdk.navigation.addPage("/rndSequencer", {
    body: root,
  });

  sdk.sidebar.registerItem("Random Sequencer", "/rndSequencer", {
    icon: "fas fa-dice",
  });
};