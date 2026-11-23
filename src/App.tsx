import React, { useState } from 'react';
import {
  CompressOutlined,
  DoubleLeftOutlined,
  DoubleRightOutlined,
  ExpandOutlined,
  ThunderboltOutlined,
} from '@ant-design/icons';
import { Button, ConfigProvider, Layout, Result, Tooltip, theme } from 'antd';
import { CliOutputPanel } from './components/CliOutputPanel';
import { InspectorPanel } from './components/InspectorPanel';
import { TopBar } from './components/TopBar';
import { TopologyCanvas } from './components/TopologyCanvas';
import { PRESET_TOPOLOGIES } from './data/presets';
import { useSimStore } from './store/useSimStore';

interface ErrorBoundaryState {
  error: Error | null;
}

class AppErrorBoundary extends React.Component<
  { children: React.ReactNode },
  ErrorBoundaryState
> {
  state: ErrorBoundaryState = { error: null };

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error('Tailwind UI render error:', error, info);
  }

  render() {
    if (this.state.error) {
      return (
        <div className="flex h-screen w-screen items-center justify-center bg-[#0b1120] p-6">
          <Result
            status="error"
            title="UI Render Error"
            subTitle={this.state.error.message || 'An unexpected error occurred while rendering the topology.'}
            extra={[
              <Button
                key="reset"
                type="primary"
                onClick={() => {
                  useSimStore.getState().loadPreset(PRESET_TOPOLOGIES[0].id);
                  this.setState({ error: null });
                }}
              >
                Reset to Default Preset
              </Button>,
              <Button
                key="retry"
                onClick={() => this.setState({ error: null })}
              >
                Dismiss
              </Button>,
            ]}
          />
        </div>
      );
    }
    return this.props.children;
  }
}

const StatusBar: React.FC = () => {
  const simResult = useSimStore((s) => s.simResult);
  const topology = useSimStore((s) => s.topology);
  const themeMode = useSimStore((s) => s.themeMode);
  const isLight = themeMode === 'light';

  return (
    <footer
      className={`flex h-6 shrink-0 items-center justify-between border-t px-3 text-[11px] select-none ${
        isLight
          ? 'border-black/[0.08] bg-[#f9f9fb] text-[#636366]'
          : 'border-white/[0.08] bg-[#1c1c1e] text-[#98989d]'
      }`}
    >
      <div className="flex items-center gap-3 font-mono">
        <span
          className={`inline-flex items-center gap-1 ${
            isLight ? 'text-[#188038]' : 'text-[#30d158]'
          }`}
        >
          <ThunderboltOutlined className="text-[10px]" />
          {simResult.computeTimeMs.toFixed(2)}ms · {simResult.convergedIterations}{' '}
          {simResult.convergedIterations === 1 ? 'iteration' : 'iterations'}
        </span>
        <span className={isLight ? 'text-black/15' : 'text-white/20'}>|</span>
        <span>
          {topology.nodes.length} nodes · {topology.links.length} links
        </span>
      </div>
      <div className="flex items-center gap-3">
        <span
          className={
            simResult.warnings.length > 0
              ? isLight
                ? 'font-medium text-[#b45309]'
                : 'text-[#ff9f0a]'
              : isLight
                ? 'text-[#636366]'
                : 'text-[#98989d]'
          }
        >
          {simResult.warnings.length} {simResult.warnings.length === 1 ? 'warning' : 'warnings'}
        </span>
      </div>
    </footer>
  );
};

export const App: React.FC = () => {
  const themeMode = useSimStore((s) => s.themeMode);
  const isDark = themeMode === 'dark';
  const [sidePanelCollapsed, setSidePanelCollapsed] = useState(false);
  const [rightSplit, setRightSplit] = useState<'split' | 'inspector' | 'cli'>('split');

  return (
    <ConfigProvider
      theme={{
        algorithm: isDark ? theme.darkAlgorithm : theme.defaultAlgorithm,
        token: {
          colorPrimary: isDark ? '#0a84ff' : '#007aff',
          colorInfo: isDark ? '#0a84ff' : '#007aff',
          colorSuccess: isDark ? '#30d158' : '#34c759',
          colorWarning: isDark ? '#ff9f0a' : '#ff9500',
          colorError: isDark ? '#ff453a' : '#ff3b30',
          colorBgBase: isDark ? '#000000' : '#f2f2f7',
          colorBgContainer: isDark ? '#1c1c1e' : '#ffffff',
          colorBgElevated: isDark ? '#2c2c2e' : '#ffffff',
          colorBgLayout: isDark ? '#000000' : '#f2f2f7',
          colorBorder: isDark ? 'rgba(255, 255, 255, 0.1)' : 'rgba(60, 60, 67, 0.18)',
          colorBorderSecondary: isDark ? 'rgba(255, 255, 255, 0.07)' : 'rgba(60, 60, 67, 0.1)',
          colorText: isDark ? '#f5f5f7' : '#1c1c1e',
          colorTextSecondary: isDark ? '#98989d' : '#636366',
          borderRadius: 10,
          borderRadiusLG: 14,
          borderRadiusSM: 8,
          fontSize: 12,
          fontFamily:
            "'SF Pro Text', 'SF Pro Display', 'Inter', -apple-system, BlinkMacSystemFont, sans-serif",
          fontFamilyCode:
            "'SF Mono', 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
        },
        components: {
          Card: {
            colorBgContainer: isDark ? '#1c1c1e' : '#ffffff',
            colorBorderSecondary: isDark ? 'rgba(255, 255, 255, 0.08)' : 'rgba(60, 60, 67, 0.12)',
          },
          Input: {
            colorBgContainer: isDark ? '#2c2c2e' : '#ffffff',
            colorBorder: isDark ? 'rgba(255, 255, 255, 0.09)' : 'rgba(60, 60, 67, 0.2)',
            activeBorderColor: isDark ? '#0a84ff' : '#007aff',
          },
          InputNumber: {
            colorBgContainer: isDark ? '#2c2c2e' : '#ffffff',
            colorBorder: isDark ? 'rgba(255, 255, 255, 0.09)' : 'rgba(60, 60, 67, 0.2)',
          },
          Select: {
            colorBgContainer: isDark ? '#2c2c2e' : '#ffffff',
            colorBorder: isDark ? 'rgba(255, 255, 255, 0.09)' : 'rgba(60, 60, 67, 0.2)',
            optionSelectedBg: isDark ? 'rgba(10, 132, 255, 0.2)' : 'rgba(0, 122, 255, 0.12)',
          },
          Button: {
            defaultBg: isDark ? '#2c2c2e' : '#ffffff',
            defaultBorderColor: isDark ? 'rgba(255, 255, 255, 0.1)' : 'rgba(60, 60, 67, 0.18)',
            defaultColor: isDark ? '#f5f5f7' : '#1c1c1e',
          },
          Modal: {
            contentBg: isDark ? '#1c1c1e' : '#ffffff',
            headerBg: isDark ? '#1c1c1e' : '#ffffff',
          },
          Drawer: {
            colorBgElevated: isDark ? '#1c1c1e' : '#ffffff',
          },
        },
      }}
    >
      <AppErrorBoundary>
        <Layout
          className={`!h-screen !w-screen overflow-hidden ${
            isDark ? '!bg-black' : '!bg-[#f2f2f7]'
          }`}
        >
          <TopBar />
          <Layout.Content className="grid flex-1 grid-cols-1 overflow-hidden lg:grid-cols-12">
            <div
              className={`relative overflow-hidden ${
                sidePanelCollapsed
                  ? 'h-full lg:col-span-12'
                  : `h-[45vh] border-b lg:col-span-7 lg:h-full lg:border-b-0 lg:border-r ${
                      isDark ? 'border-white/[0.08]' : 'border-black/[0.09]'
                    }`
              }`}
            >
              <TopologyCanvas />
              <Tooltip
                title={sidePanelCollapsed ? 'Show Inspector & CLI' : 'Collapse Inspector & CLI'}
                placement="left"
              >
                <button
                  type="button"
                  onClick={() => setSidePanelCollapsed((v) => !v)}
                  className={`absolute top-3 right-3 z-20 inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-[11px] font-medium shadow-md backdrop-blur-xl transition-colors ${
                    isDark
                      ? 'border-white/[0.1] bg-[#1c1c1e]/80 text-[#f5f5f7] hover:bg-[#2c2c2e]'
                      : 'border-black/[0.12] bg-white/85 text-[#1c1c1e] hover:bg-[#f2f2f7]'
                  }`}
                >
                  {sidePanelCollapsed ? (
                    <>
                      <DoubleLeftOutlined className="text-[10px]" />
                      <span>Inspector</span>
                    </>
                  ) : (
                    <>
                      <span>Collapse</span>
                      <DoubleRightOutlined className="text-[10px]" />
                    </>
                  )}
                </button>
              </Tooltip>
            </div>
            {!sidePanelCollapsed && (
              <div
                className={`flex h-[55vh] flex-col overflow-hidden lg:col-span-5 lg:h-full ${
                  isDark ? 'bg-[#121214]' : 'bg-[#f2f2f7]'
                }`}
              >
                <div
                  className={`relative overflow-hidden border-b transition-all duration-150 ${
                    isDark ? 'border-white/[0.08]' : 'border-black/[0.09]'
                  } ${
                    rightSplit === 'inspector'
                      ? 'flex-1'
                      : rightSplit === 'cli'
                        ? 'h-9 shrink-0'
                        : 'h-[48%]'
                  }`}
                >
                  {rightSplit === 'cli' ? (
                    <div
                      onClick={() => setRightSplit('split')}
                      className={`flex h-full cursor-pointer items-center justify-between px-3.5 text-xs font-medium ${
                        isDark ? 'bg-[#1c1c1e] text-[#f5f5f7] hover:bg-[#2c2c2e]' : 'bg-white text-[#1c1c1e] hover:bg-black/[0.04]'
                      }`}
                    >
                      <span>Device Inspector (Minimized)</span>
                      <span className="inline-flex items-center gap-1 text-[11px] text-[#0a84ff]">
                        <CompressOutlined /> Restore Split
                      </span>
                    </div>
                  ) : (
                    <InspectorPanel
                      headerExtra={
                        <Tooltip title={rightSplit === 'inspector' ? 'Restore 50/50 Split' : 'Expand Inspector'}>
                          <Button
                            size="small"
                            type="text"
                            icon={rightSplit === 'inspector' ? <CompressOutlined /> : <ExpandOutlined />}
                            onClick={() =>
                              setRightSplit((prev) => (prev === 'inspector' ? 'split' : 'inspector'))
                            }
                          >
                            {rightSplit === 'inspector' ? 'Split' : 'Expand'}
                          </Button>
                        </Tooltip>
                      }
                    />
                  )}
                </div>
                <div
                  className={`relative overflow-hidden transition-all duration-150 ${
                    rightSplit === 'cli'
                      ? 'flex-1'
                      : rightSplit === 'inspector'
                        ? 'h-9 shrink-0'
                        : 'h-[52%]'
                  }`}
                >
                  {rightSplit === 'inspector' ? (
                    <div
                      onClick={() => setRightSplit('split')}
                      className={`flex h-full cursor-pointer items-center justify-between px-3.5 text-xs font-medium ${
                        isDark ? 'bg-[#1c1c1e] text-[#f5f5f7] hover:bg-[#2c2c2e]' : 'bg-white text-[#1c1c1e] hover:bg-black/[0.04]'
                      }`}
                    >
                      <span>Routing &amp; CLI Diagnostics (Minimized)</span>
                      <span className="inline-flex items-center gap-1 text-[11px] text-[#0a84ff]">
                        <CompressOutlined /> Restore Split
                      </span>
                    </div>
                  ) : (
                    <CliOutputPanel
                      headerExtra={
                        <Tooltip title={rightSplit === 'cli' ? 'Restore 50/50 Split' : 'Expand CLI & Diagnostics'}>
                          <Button
                            size="small"
                            icon={rightSplit === 'cli' ? <CompressOutlined /> : <ExpandOutlined />}
                            onClick={() =>
                              setRightSplit((prev) => (prev === 'cli' ? 'split' : 'cli'))
                            }
                          >
                            {rightSplit === 'cli' ? 'Split' : 'Expand'}
                          </Button>
                        </Tooltip>
                      }
                    />
                  )}
                </div>
              </div>
            )}
          </Layout.Content>
          <StatusBar />
        </Layout>
      </AppErrorBoundary>
    </ConfigProvider>
  );
};

export default App;
