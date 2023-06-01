package rlweipfebig;

import java.util.Arrays;

/**
 * Methods for checking array dimensions.
 */
public class CheckB {

	public static boolean checkDims(int[] arr, int dim0) {
		return arr.length == dim0;
	}

	public static boolean checkDims(int[][] arr, int dim0, int dim1) {
		return arr.length == dim0 && Arrays.stream(arr).allMatch(arr1->checkDims(arr1, dim1));
	}

	public static boolean checkDims(int[][][] arr, int dim0, int dim1, int dim2) {
		return arr.length == dim0 && Arrays.stream(arr).allMatch(arr1->checkDims(arr1, dim1, dim2));
	}

	public static boolean checkDims(Object[] arr, int dim0) {
		return arr.length == dim0;
	}

	public static boolean checkDims(Object[][] arr, int dim0, int dim1) {
		return arr.length == dim0 && Arrays.stream(arr).allMatch(arr1->checkDims(arr1, dim1));
	}

	public static boolean checkDims(Object[][][] arr, int dim0, int dim1, int dim2) {
		return arr.length == dim0 && Arrays.stream(arr).allMatch(arr1->checkDims(arr1, dim1, dim2));
	}
}
