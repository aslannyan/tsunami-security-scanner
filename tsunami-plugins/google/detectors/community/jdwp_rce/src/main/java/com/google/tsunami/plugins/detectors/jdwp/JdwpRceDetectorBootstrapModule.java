package com.google.tsunami.plugins.detectors.jdwp;

import com.google.tsunami.plugin.PluginBootstrapModule;

/** A {@link PluginBootstrapModule} for {@link JdwpRceDetector}. */
public final class JdwpRceDetectorBootstrapModule extends PluginBootstrapModule {

  @Override
  protected void configurePlugin() {
    registerPlugin(JdwpRceDetector.class);
  }
}
