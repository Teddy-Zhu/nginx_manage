import { computed, ref } from "vue";
import type { UpdateChannel } from "../api/client";

type Channel = UpdateChannel["channel"];
type ChannelAPI = {
  updateChannel: () => Promise<UpdateChannel>;
  setUpdateChannel: (channel: Channel) => Promise<UpdateChannel>;
};

export const updateChannels = [
  { label: "稳定版", value: "stable" },
  { label: "Beta", value: "beta" },
];

export function useUpdateChannel(api: ChannelAPI) {
  const channel = ref<Channel>("stable");
  const ready = ref(false);
  const saving = ref(false);
  let generation = 0;
  async function loadChannel() {
    if (saving.value) return;
    const current = generation;
    const result = await api.updateChannel();
    if (current === generation) {
      channel.value = result.channel;
      ready.value = true;
    }
  }
  async function saveChannel(value: Channel) {
    generation++;
    saving.value = true;
    try {
      channel.value = (await api.setUpdateChannel(value)).channel;
    } finally {
      saving.value = false;
    }
  }
  return {
    channel,
    ready,
    saving,
    loadChannel,
    saveChannel,
    prerelease: computed(() => channel.value === "beta"),
  };
}
