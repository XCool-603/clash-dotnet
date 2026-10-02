<script lang="ts">
import { defineComponent } from 'vue'
import type { PropType, VNodeChild } from 'vue'

/**
 * A **constant-identity** cell renderer for `el-table-v2`.
 *
 * The tempting shortcut is
 *
 * ```html
 * <component :is="() => render(row)" />
 * ```
 *
 * which creates a brand-new component type on every render. Vue cannot patch
 * it, so it unmounts and remounts *every cell* on each WebSocket tick — at
 * ~1 Hz over hundreds of rows that is the difference between a table and a
 * slideshow.
 *
 * This component's type never changes; only its `render` prop does, so Vue
 * patches the produced vnode tree in place.
 */
export default defineComponent({
  name: 'ConnectionCell',
  props: {
    render: {
      type: Function as PropType<() => VNodeChild>,
      required: true,
    },
  },
  setup(props) {
    return (): VNodeChild => props.render()
  },
})
</script>
