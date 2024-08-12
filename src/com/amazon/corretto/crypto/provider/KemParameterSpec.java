// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.spec.AlgorithmParameterSpec;

/** This class specifies parameters for a KEM, using NIDs defined in nid.h. */
public class KemParameterSpec implements AlgorithmParameterSpec {

  // ML-KEM IPD
  public static final KemParameterSpec mlkem512ipd = new KemParameterSpec(985);
  public static final KemParameterSpec mlkem768ipd = new KemParameterSpec(986);
  public static final KemParameterSpec mlkem1024ipd = new KemParameterSpec(987);
  // PQ/T Hybrid KEMs
  public static final KemParameterSpec pqt25519 = new KemParameterSpec(988);
  public static final KemParameterSpec pqt256 = new KemParameterSpec(989);
  public static final KemParameterSpec pqt384 = new KemParameterSpec(990);

  private final int nid;

  public KemParameterSpec(int nid) {
    // TODO: do validation?
    this.nid = nid;
  }

  public int getNID() {
    return nid;
  }
}
